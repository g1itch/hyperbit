# Copyright 2015 HyperBit developers

import asyncio
import enum
import ipaddress
import os
import time
import socket
import socks

from hyperbit import config, crypto, database, net, packet


class KnownPeer(object):
    def __init__(self, host):
        self._host = host
        self.on_change = []

    def set_pending(self):
        database.db2.execute('update peers set status = 1, tries = tries + 1 where host = ?',
                (self._host,))
        for func in self.on_change:
            func()

    def set_connected(self):
        database.db2.execute('update peers set status = 2, tries = 0, timestamp = ? where host = ?',
                (int(time.time()), self._host))
        for func in self.on_change:
            func()

    def set_disconnected(self):
        database.db2.execute('update peers set status = 0 where host = ?',
                (self._host,))
        for func in self.on_change:
            func()

    @property
    def timestamp(self):
        return database.db2.execute('select timestamp from peers where host = ?', (self._host,)).fetchone()[0]

    @property
    def services(self):
        return database.db2.execute('select services from peers where host = ?', (self._host,)).fetchone()[0]

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return database.db2.execute('select port from peers where host = ?', (self._host,)).fetchone()[0]

    @port.setter
    def port(self, port):
        database.db2.execute('update peers set port = ? where host = ?', (port, self._host))
        for func in self.on_change:
            func()


class PeerManager(object):
    def __init__(self, core, inv):
        self._core = core
        database.db2.execute('create table if not exists peers (timestamp, services, host unique, port, status, tries)')
        database.db2.execute('update peers set status = 0')
        self._peers = dict()
        for host, in database.db2.execute('select host from peers'):
            self._peers[host] = KnownPeer(host)

        self.om = inv
        self.client_nonce = int.from_bytes(os.urandom(8), byteorder='big', signed=False)
        self.on_add_peer = []
        self.on_stats_changed = []

        self._connections = []
        self._endpoints = dict()

        for peer in config.KNOWN_PEERS:
            self.new_peer(0, 1, peer[0], peer[1], False)

    def send_inv(self, object):
        for conn in self._connections:
            if conn.got_version:
                conn.send_inv(object)

    def get_best_peer(self):
        for host, in database.db2.execute('select host from peers where status = 0 order by tries asc, timestamp desc limit 1'):
            return self._peers[host]
        return None

    def new_peer(self, timestamp, services, host, port, check_private=True):
        if isinstance(host, str):
            ip = ipaddress.ip_address(host)
            if check_private and ip.is_private:
                return
            if ip.version == 4:
                host = bytes.fromhex('00000000000000000000ffff')+ip.packed
            else:
                host = ip.packed
        if host in self._peers:
            database.db2.execute('update peers set timestamp = max(timestamp, ?) where host = ?',
                    (timestamp, host))
        else:
            database.db2.execute('insert into peers (timestamp, services, host, port, status, tries) values (?, ?, ?, ?, 0, 0)',
                    (timestamp, services, host, port))
        peer = KnownPeer(host)
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
        return database.db2.execute('select count(*) from peers where status = 2').fetchone()[0]

    def count_pending_and_connected(self):
        return database.db2.execute('select count(*) from peers where status = 1 or status = 2').fetchone()[0]

    @asyncio.coroutine
    def run(self):
        if self._core.get_config('network.proxy') == 'tor':
            if self._core.get_config('network.proxy') == 'tor':
                host = self._core.get_config('network.tor_host')
                port = self._core.get_config('network.tor_port')
                socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, host, port, True)
                socket.socket = socks.socksocket
        elif self._core.get_config('network.proxy') == 'disabled':
            asyncio.get_event_loop().create_task(self._run2())
        if self._core.get_config('network.proxy') == 'trusted':
            while True:
                host = self._core.get_config('network.trusted_host')
                port = self._core.get_config('network.trusted_port')
                print('trying', host, port)
                c = PacketConnection(net.Connection(net.ipv6(host), port))
                conn = Connection2(om=self.om, peers=self, connection=c)
                self._connections.append(conn)
                yield from conn.run()
                yield from asyncio.sleep(10)
        else:
            while True:
                if self.count_connected() < config.CONNECTION_COUNT\
                        and self.count_pending_and_connected() < self.count_all():
                    self._open_one()
                while self.count_pending_and_connected() < config.CONNECTION_COUNT\
                        and self.count_pending_and_connected() < self.count_all():
                    self._open_one()
                yield from asyncio.sleep(10)

    @asyncio.coroutine
    def _run2(self):
        l = net.Listener(self._core.get_config('network.listen_port', config.LISTEN_PORT))
        while True:
            connection = yield from l.accept()
            c = PacketConnection(connection)
            conn = Connection2(om=self.om, peers=self, connection=c)
            self._connections.append(conn)
            conn.on_connect.append(lambda: self._on_connect(connection.remote_host.packed))
            conn.on_disconnect.append(lambda: self._on_disconnect(connection.remote_host.packed))
            asyncio.get_event_loop().create_task(conn.run())

    def _on_connect(self, host):
        self._peers[host].set_connected()
        for func in self.on_stats_changed:
            func()

    def _on_disconnect(self, host):
        self._peers[host].set_disconnected()
        for func in self.on_stats_changed:
            func()

    def _open_one(self):
        best_peer = self.get_best_peer()
        if best_peer is not None:
            host = best_peer.host
            port = best_peer.port
            print('trying', ipaddress.ip_address(host), port)
            best_peer.set_pending()
            c = PacketConnection(net.Connection(net.ipv6(host), port))
            conn = Connection2(om=self.om, peers=self, connection=c)
            self._connections.append(conn)
            conn.on_connect.append(lambda: self._on_connect(host))
            conn.on_disconnect.append(lambda: self._on_disconnect(host))
            asyncio.get_event_loop().create_task(conn.run())
            #conn.set_host_port(host, port)

    def count_all(self):
        return len(self._peers)

    def get_addresses(self):
        addresses = []
        #for peer in self._peers:
        #    addresses.append(packet.Address(peer.timestamp, 1, peer.services, peer.host, peer.port))
        return addresses


class PacketConnection(object):
    def __init__(self, connection):
        self._c = connection
        self.remote_host = connection.remote_host

    @asyncio.coroutine
    def connect(self):
        return (yield from self._c.connect())

    def send_packet(self, payload):
        magic = 0xe9beb4d9
        command = payload.command
        payloaddata = payload.data
        length = len(payloaddata)
        checksum = crypto.sha512(payloaddata)[:4]
        header = packet.Header(magic, command, length, checksum)
        self._c.send(header.to_bytes())
        self._c.send(payloaddata)

    @asyncio.coroutine
    def recv_packet(self):
        headerdata = b''
        while len(headerdata) < 24:
            buf = yield from self._c.recv(24 - len(headerdata))
            if not buf:
                return None
            headerdata += buf
        header = packet.Header.from_bytes(headerdata)
        if header.magic != 0xe9beb4d9:
            return None
        payloaddata = b''
        while len(payloaddata) < header.length:
            buf = yield from self._c.recv(header.length - len(payloaddata))
            if not buf:
                return None
            payloaddata += buf
        if header.checksum != crypto.sha512(payloaddata)[:4]:
            return None
        return packet.Generic(header.command, payloaddata)


class Connection2(object):
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

    def send_inv(self, object):
        inv = packet.Inv()
        inv.hashes.append(object.hash)
        self._c.send_packet(inv)

    @asyncio.coroutine
    def handle_version(self, payload):
        assert payload.nonce != self.peers.client_nonce
        assert payload.version >= 3
        assert 1 in payload.streams
        self.remote_user_agent = payload.useragent
        print(payload.version, payload.useragent)
        verack = packet.Verack()
        self._c.send_packet(verack)
        addr = packet.Addr()
        addr.addresses = self.peers.get_addresses()
        self._c.send_packet(addr)
        hashes = self.om.get_hashes_for_send()
        for i in range(0, len(hashes), 50000):
            inv = packet.Inv()
            inv.hashes = hashes[i:i+50000]
            self._c.send_packet(inv)
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
        version = packet.Version()
        version.useragent = config.USER_AGENT
        version.nonce = self.peers.client_nonce
        version.src_port = config.LISTEN_PORT
        self._c.send_packet(version)
        generic = yield from self._c.recv_packet()
        while generic:
            if not self.got_version:
                if generic.command == 'version':
                    yield from self.handle_version(packet.Version(generic.data))
            if not self.got_verack:
                if generic.command == 'verack':
                    payload = packet.Verack(generic.data)
                    self.got_verack = True
            if self.got_version and self.got_verack:
                if generic.command == 'addr':
                    addr = packet.Addr(generic.data)
                    for address in addr.addresses:
                        if address.stream == 1:
                            self.peers.new_peer(address.time, address.services, address.ip, address.port)
                elif generic.command == 'inv':
                    inv = packet.Inv(generic.data)
                    getdata = packet.Getdata()
                    for hash in inv.hashes:
                        object = self.om.get_object(hash)
                        if object is None:
                            getdata.hashes.append(hash)
                    if len(getdata.hashes) > 0:
                        self._c.send_packet(getdata)
                elif generic.command == 'getdata':
                    getdata = packet.Getdata(generic.data)
                    for hash in getdata.hashes:
                        object = self.om.get_object(hash)
                        if object is not None:
                            self._c.send_packet(object)
                            yield
                elif generic.command == 'object':
                    object = packet.Object(generic.data)
                    self.om.add_object(object)
            generic = yield  from self._c.recv_packet()

        for func in self.on_disconnect:
            func()

        self.peers._connections.remove(self)
