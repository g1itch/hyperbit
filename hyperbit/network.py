# Copyright 2015-2021 HyperBit developers
# pylint: disable=too-many-instance-attributes

import asyncio
import ipaddress
import logging
import os
import socket
import time

try:
    import socks
except ImportError:
    socks = None

try:
    import aioupnp
    from aioupnp.upnp import UPnP
except ImportError:
    UPnP = None

from hyperbit import config, crypto, net, packet, __version__

logger = logging.getLogger(__name__)


class KnownPeer():
    def __init__(self, db, host):
        self._db = db
        self._host = host
        self.on_change = []

    def set_pending(self):
        self._db.execute(
            'UPDATE peers SET status = 1, tries = tries + 1 WHERE host = ?',
            (self._host,))
        for func in self.on_change:
            func()

    def set_connected(self):
        self._db.execute(
            'UPDATE peers SET status = 2, tries = 0, timestamp = ?'
            ' WHERE host = ?', (int(time.time()), self._host))
        for func in self.on_change:
            func()

    def set_disconnected(self):
        self._db.execute(
            'UPDATE peers SET status = 0 WHERE host = ?', (self._host,))
        for func in self.on_change:
            func()

    @property
    def timestamp(self):
        return self._db.execute(
            'SELECT timestamp FROM peers WHERE host = ?', (self._host,)
        ).fetchone()[0]

    @property
    def services(self):
        return self._db.execute(
            'SELECT services FROM peers WHERE host = ?', (self._host,)
        ).fetchone()[0]

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._db.execute(
            'SELECT port FROM peers WHERE host = ?', (self._host,)
        ).fetchone()[0]

    @port.setter
    def port(self, port):
        self._db.execute(
            'UPDATE peers SET port = ? WHERE host = ?', (port, self._host))
        for func in self.on_change:
            func()


class PeerManager():
    def __init__(self, core, db, inv):
        logger.debug('start')
        self._core = core
        self._db = db
        self._db.execute(
            'CREATE TABLE IF NOT EXISTS peers'
            ' (timestamp, services, host unique, port, status, tries)')
        self._db.execute('update peers set status = 0')
        self._peers = dict()
        for host, in self._db.execute('SELECT host FROM peers'):
            self._peers[host] = KnownPeer(self._db, host)

        self.om = inv
        self.client_nonce = int.from_bytes(
            os.urandom(8), byteorder='big', signed=False)
        self.on_add_peer = []
        self.on_stats_changed = []

        self._connections = []
        self._endpoints = dict()

        self._trusted_status = 0

        for peer in config.KNOWN_PEERS:
            self.new_peer(0, 1, peer[0], peer[1], False)

    def send_inv(self, obj):
        closed = []
        for conn in self._connections:
            if conn.got_version:
                if conn.send_inv(obj) is False:
                    closed.append(conn)
        for conn in closed:
            self._on_disconnect(conn)

    def get_best_peer(self):
        for host, in self._db.execute(
                'SELECT host FROM peers WHERE status = 0'
                ' ORDER BY tries ASC, timestamp DESC LIMIT 1'):
            return self._peers[host]
        return None

    def new_peer(self, timestamp, services, host, port, check_private=True):
        if isinstance(host, str):
            ip = ipaddress.ip_address(host)
            if check_private and ip.is_private:
                return
            if ip.version == 4:
                host = bytes.fromhex('00000000000000000000ffff') + ip.packed
            else:
                host = ip.packed
        if host in self._peers:
            self._db.execute(
                'UPDATE peers SET timestamp = max(timestamp, ?)'
                ' WHERE host = ?', (timestamp, host))
        else:
            self._db.execute(
                'INSERT INTO peers'
                ' (timestamp, services, host, port, status, tries)'
                ' VALUES (?, ?, ?, ?, 0, 0)',
                (timestamp, services, host, port))
        peer = KnownPeer(self._db, host)
        self._peers[host] = peer
        for func in self.on_add_peer:
            func(peer)
        for func in self.on_stats_changed:
            func()
        return peer

    @property
    def peers(self):
        return self._peers.values()

    def count_connected(self):
        return self._db.execute(
            'SELECT count(*) FROM peers WHERE status = 2'
        ).fetchone()[0] + (self._trusted_status == 2)

    def count_pending_and_connected(self):
        return self._db.execute(
            'SELECT count(*) FROM peers WHERE status = 1 or status = 2'
        ).fetchone()[0] + (self._trusted_status in [1, 2])

    @asyncio.coroutine
    def run(self):
        if self._core.get_config('network.proxy') == 'tor' and socks:
            logger.info('connecting through tor')
            if self._core.get_config('network.proxy') == 'tor':
                host = self._core.get_config('network.tor_host')
                port = self._core.get_config('network.tor_port')
                socks.set_default_proxy(
                    socks.PROXY_TYPE_SOCKS5, host, port, True)
                socket.socket = socks.socksocket
        elif self._core.get_config('network.proxy') == 'disabled':
            logger.info('connecting directly to the internet')
            asyncio.get_event_loop().create_task(self._run_inbound())
        if self._core.get_config('network.proxy') == 'trusted':
            logger.info('connecting to trusted peer')
            while True:
                host = self._core.get_config('network.trusted_host')
                port = self._core.get_config('network.trusted_port')
                logger.info('trying %s %s', host, port)
                self._trusted_status = 1
                c = PacketConnection(net.Connection(net.ipv6(host), port))
                conn = Connection2(om=self.om, peers=self, connection=c)
                self._connections.append(conn)

                def on_connect():
                    self._trusted_status = 2
                    for func in self.on_stats_changed:
                        func()

                conn.on_connect.append(on_connect)
                yield from conn.run()
                self._trusted_status = 0
                for func in self.on_stats_changed:
                    func()
                yield from asyncio.sleep(10)
        else:
            while True:
                if (
                    self.count_connected() < config.CONNECTION_COUNT
                    and self.count_pending_and_connected() < self.count_all()
                ):
                    self._open_one()
                while (
                    self.count_pending_and_connected()
                    < config.CONNECTION_COUNT
                    and self.count_pending_and_connected() < self.count_all()
                ):
                    self._open_one()
                yield from asyncio.sleep(10)

    async def _run_inbound(self):
        port = self._core.get_config('network.listen_port')
        listener = net.Listener(port)
        listener.listen()

        if UPnP:
            try:
                upnp = await UPnP.discover()
            except aioupnp.fault.UPnPError:
                logger.warning('UPnP is not available')
            else:
                ext_ip = await upnp.get_external_ip()
                logging.info('External IP is %s', ext_ip)
                await upnp.add_port_mapping(
                    port, 'TCP', port, upnp.lan_address, 'HyperBit bitmessage')

        while True:
            connection = await listener.accept()
            if not connection:
                continue
            self.new_peer(
                int(time.time()), 1,
                connection.remote_host.packed, connection.remote_port)
            c = PacketConnection(connection)
            conn = Connection2(om=self.om, peers=self, connection=c)
            self._connections.append(conn)
            conn.on_connect.append(
                lambda: self._on_connect(connection.remote_host.packed))
            conn.on_disconnect.append(
                lambda: self._on_disconnect(connection))
            asyncio.get_event_loop().create_task(conn.run())
        await upnp.delete_port_mapping(port, 'TCP')

    def _on_connect(self, host):
        self._peers[host].set_connected()
        for func in self.on_stats_changed:
            func()

    def _on_disconnect(self, conn):
        self._connections.remove(conn)
        try:
            self._peers[conn.remote_host.packed].set_disconnected()
        except KeyError:
            logger.warning(  # should be trusted peer
                'No such peer %s', ipaddress.ip_address(conn.remote_host))
            pass
        for func in self.on_stats_changed:
            func()

    def _open_one(self):
        best_peer = self.get_best_peer()
        if best_peer is not None:
            host = best_peer.host
            port = best_peer.port
            logger.info('trying %s %s', ipaddress.ip_address(host), port)
            best_peer.set_pending()
            c = PacketConnection(net.Connection(net.ipv6(host), port))
            conn = Connection2(om=self.om, peers=self, connection=c)
            self._connections.append(conn)
            conn.on_connect.append(lambda: self._on_connect(host))
            conn.on_disconnect.append(lambda: self._on_disconnect(conn))
            asyncio.get_event_loop().create_task(conn.run())
            # conn.set_host_port(host, port)

    def count_all(self):
        return len(self._peers)

    def get_addresses(self):
        addresses = []
        # for peer in self._peers:
        #     addresses.append(packet.Address(
        #         peer.timestamp, config.NETWORK_STREAM, peer.services,
        #         peer.host, peer.port
        #     ))
        return addresses


class PacketConnection():
    """A connection for sending and receiving Bitmessage packets"""
    def __init__(self, connection):
        self._c = connection
        self.remote_host = connection.remote_host

    @asyncio.coroutine
    def connect(self):
        """Establish a connection. Return True on succes, else return False."""
        return (yield from self._c.connect())

    def send_packet(self, payload):
        """Send a Bitmessage packet."""
        logger.debug('sending %s packet', payload.command)
        magic = 0xe9beb4d9
        command = payload.command
        payloaddata = payload.data
        length = len(payloaddata)
        checksum = crypto.sha512(payloaddata)[:4]
        header = packet.Header(magic, command, length, checksum)
        return (
            self._c.send(header.to_bytes())
            and self._c.send(payloaddata))

    @asyncio.coroutine
    def recv_packet(self):
        """Receive a Bitmessage packet, or return None in case of failure."""
        headerdata = yield from self._c.recv(24)
        if headerdata is None:
            return None
        header = packet.Header.from_bytes(headerdata)
        if header.magic != 0xe9beb4d9:
            return None
        payloaddata = yield from self._c.recv(header.length)
        if payloaddata is None:
            return None
        if header.checksum != crypto.sha512(payloaddata)[:4]:
            return None
        logger.debug('received %s packet', header.command)
        return packet.Generic(header.command, payloaddata)


class Connection2():
    def __init__(self, om, peers, connection):
        self.om = om
        self.peers = peers
        self._c = connection

        self.on_connect = []
        self.on_disconnect = []

        self.got_version = False
        self.got_verack = False
        self.remote_host = self._c.remote_host
        self.remote_port = None
        self.remote_user_agent = None
        self.fully_established = False
        self.inbound = connection._c.inbound

    def send_inv(self, obj):
        return self._c.send_packet(packet.Inv(
            hashes=[obj.hash]
        ))

    @asyncio.coroutine
    def handle_version(self, payload):
        assert payload.nonce != self.peers.client_nonce
        assert payload.version >= 3
        assert config.NETWORK_STREAM in payload.streams
        self.remote_user_agent = payload.user_agent
        logger.info('remote user agent is %s', payload.user_agent)
        self._c.send_packet(packet.Verack())
        self._c.send_packet(packet.Addr(self.peers.get_addresses()))
        hashes = self.om.get_hashes_for_send()
        for i in range(0, len(hashes), 50000):
            self._c.send_packet(packet.Inv(
                hashes=hashes[i:i+50000]
            ))
        self.remote_port = payload.src_port
        for func in self.on_connect:
            func()
        self.got_version = True

    @asyncio.coroutine
    def run(self):
        connected = yield from self._c.connect()
        if not connected:
            for func in self.on_disconnect:
                func()
            return
        logger.info('connected %s', ipaddress.ip_address(self.remote_host))
        self._c.send_packet(packet.Version(
            version=3,
            services=1,
            timestamp=int(time.time()),
            dst_services=1,
            dst_ip=16 * b'\x00',
            dst_port=8444,
            src_services=1,
            src_ip=16 * b'\x00',
            src_port=8444,  # FIXME send correct port number
            nonce=self.peers.client_nonce,
            user_agent='/HyperBit:' + __version__ + '/',
            streams=[config.NETWORK_STREAM]
        ))
        generic = yield from self._c.recv_packet()
        while generic:
            if not self.got_version:
                if generic.command == 'version':
                    try:
                        yield from self.handle_version(
                            packet.Version.from_bytes(generic.data))
                    except AssertionError:
                        return
            if not self.got_verack:
                if generic.command == 'verack':
                    packet.Verack.from_bytes(generic.data)
                    self.got_verack = True
            if self.got_version and self.got_verack:
                # No TLS currently
                self.fully_established = True
                if generic.command == 'addr':
                    addr = packet.Addr.from_bytes(generic.data)
                    for address in addr.addresses:
                        if address.stream == config.NETWORK_STREAM:
                            self.peers.new_peer(
                                address.time, address.services,
                                address.ip, address.port)
                elif generic.command == 'inv':
                    inv = packet.Inv.from_bytes(generic.data)
                    getdata = packet.Getdata([])
                    for invhash in inv.hashes:
                        obj = self.om.get_object(invhash)
                        if obj is None:
                            getdata.hashes.append(invhash)
                    new_hashes = len(getdata.hashes)
                    if new_hashes > 0:
                        logger.info(
                            'send getdata for %s hashes', new_hashes)
                        if self._c.send_packet(getdata) is False:
                            break
                elif generic.command == 'getdata':
                    getdata = packet.Getdata.from_bytes(generic.data)
                    logger.info(
                        'received getdata for %s hashes', len(getdata.hashes))
                    for invhash in getdata.hashes:
                        obj = self.om.get_object(invhash)
                        if obj is not None:
                            if self._c.send_packet(obj) is False:
                                self.set_disconnected()
                                return
                            yield
                elif generic.command == 'object':
                    obj = packet.Object.from_bytes(generic.data)
                    self.om.add_object(obj)
                elif generic.command == 'ping':
                    self._c.send_packet(packet.Generic('pong', ''))
                else:
                    logger.warning('unsuitable command %s', generic.command)

            # FIXME: there is a possibility for unknown command
            # before fully_established
            try:
                generic = yield from self._c.recv_packet()
            except OSError:
                logger.warning('OSError in connection loop', exc_info=True)
                break

        self.set_disconnected()

    def set_disconnected(self):
        for func in self.on_disconnect:
            func()
        logger.info('disconnected %s', ipaddress.ip_address(self.remote_host))
