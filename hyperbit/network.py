# Copyright 2015 HyperBit developers

import asyncio
import time

from hyperbit import crypto, config, packet, database
import ipaddress
import enum



class PeerStatus(enum.Enum):
    disconnected = 0
    pending = 1
    connected = 2



class PeerInfo(object):
    def __init__(self):
        self.timestamp = 0
        self.services = 0
        self.host = bytes(16)
        self.port = 0
        self.status = PeerStatus.disconnected

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
    def __init__(self, inv):
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

        self.new_peer(0, 1, '212.47.234.146', 8444)
        self.new_peer(0, 1, '213.220.247.85', 8444)
        self.new_peer(0, 1, '45.63.64.229', 8444)
        self.new_peer(0, 1, '72.160.6.112', 8444)
        self.new_peer(0, 1, '84.42.251.196', 8444)
        self.new_peer(0, 1, '109.160.25.40', 8444)
        self.new_peer(0, 1, '158.222.217.190', 8080)

        asyncio.get_event_loop().create_task(self._run())

    def get_best_peer(self):
        for host, in database.db2.execute('select host from peers where status = 0 order by tries asc, timestamp desc limit 1'):
            return self._peers[host]
        return None

    def new_peer(self, timestamp, services, host, port):
        if isinstance(host, str):
            ip = ipaddress.ip_address(host)
            if ip.is_private:
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
        return peer

    @property
    def peers(self):
        return self._peers.values()

    def count_connected(self):
        return database.db2.execute('select count(*) from peers where status = 2').fetchone()[0]

    def count_pending_and_connected(self):
        return database.db2.execute('select count(*) from peers where status = 1 or status = 2').fetchone()[0]

    @asyncio.coroutine
    def _run(self):
        yield from asyncio.start_server(self._handle_connection, port=config.LISTEN_PORT)
        while True:
            if self.count_connected() < config.CONNECTION_COUNT\
                    and self.count_pending_and_connected() < self.count_all():
                self._open_one()
            while self.count_pending_and_connected() < config.CONNECTION_COUNT\
                    and self.count_pending_and_connected() < self.count_all():
                self._open_one()
            yield from asyncio.sleep(10)

    def _handle_connection(self, reader, writer):
        conn = Connection(om=self.om, peers=self)
        host, port = writer.get_extra_info('peername')
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            host = bytes.fromhex('00000000000000000000ffff')+ip.packed
        else:
            host = ip.packed
        conn.on_connect.append(lambda: self._on_connect(host))
        conn.on_disconnect.append(lambda: self._on_disconnect(host))
        conn.set_reader_writer(reader, writer)

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
            conn = Connection(om=self.om, peers=self)
            self._connections.append(conn)
            conn.on_connect.append(lambda: self._on_connect(host))
            conn.on_disconnect.append(lambda: self._on_disconnect(host))
            conn.set_host_port(host, port)

    def add_endpoint(self, endpoint, timestamp):
        if endpoint not in self._endpoints:
            self._endpoints[endpoint] = timestamp
            #if len(self.connections) < 8:
            #    endpoint, timestamp = self._endpoints.popitem()
            #    host = str(ipaddress.ip_address(endpoint.ip))
            #    port = endpoint.port
            #    print(host, port)
            #    self._loop.create_task(Connection.open(host, port, loop=loop, om=om, peers=peers))
            #    self.connections.append(1)#FIXME
        elif self._endpoints[endpoint] < timestamp:
            self._endpoints[endpoint] = timestamp


    def add(self, new_peer):
        if new_peer.stream == 1:
            self.new_peer(new_peer.time, new_peer.services, new_peer.ip, new_peer.port)
        for func in self.on_stats_changed:
            func()

    def count_all(self):
        return len(self._peers)

    def get_addresses(self):
        addresses = []
        #for peer in self._peers:
        #    addresses.append(packet.Address(peer.timestamp, 1, peer.services, peer.host, peer.port))
        return addresses

import os
class Connection(object):
    def __init__(self, om, peers):
        self.om = om
        self.peers = peers

        self.on_connect = []
        self.on_disconnect = []

        self.got_version = False
        self.got_verack = False
        self.remote_host = None
        self.remote_port = None
        self.remote_user_agent = None

    def set_host_port(self, host, port):
        self.remote_host = host
        self.remote_port = port
        asyncio.get_event_loop().create_task(self._connect())


    def _connect(self):
        host = str(ipaddress.IPv4Address(self.remote_host[-4:]))
        port = self.remote_port
        #print(host, port)
        try:
            reader, writer = yield from asyncio.open_connection(host, port, loop=asyncio.get_event_loop())
        except:
            print('EXCEPTION')
            for func in self.on_disconnect:
                func()
        else:
            self.set_reader_writer(reader, writer)

    def set_reader_writer(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.om.on_add_object.append(self._on_add_object)
        asyncio.get_event_loop().create_task(self._run())


    def write(self, payload):
        header = packet.Header()
        header.command = payload.command
        payloaddata = payload.data
        header.length = len(payloaddata)
        header.checksum = crypto.sha512(payloaddata)[:4]
        #print('SEND', header.command, header.length)
        self.writer.write(header.data)
        self.writer.write(payloaddata)

    def _read(self):
        headerdata = yield from self.reader.readexactly(24)
        header = packet.Header(headerdata)
        payloaddata = yield from self.reader.readexactly(header.length)
        assert header.magic == 0xe9beb4d9
        assert header.checksum == crypto.sha512(payloaddata)[:4]
        #print('RECV', header.command,header.length)
        return header, payloaddata

    @asyncio.coroutine
    def _run(self):
        reader = self.reader
        version = packet.Version()
        version.useragent = config.USER_AGENT
        version.nonce = self.peers.client_nonce
        version.src_port = config.LISTEN_PORT
        self.write(version)
        yield from self.writer.drain()
        try:
            while True:
                header, payloaddata = yield from self._read()
                if not self.got_version:
                    if header.command == 'version':
                        payload = packet.Version(payloaddata)
                        assert payload.nonce != self.peers.client_nonce
                        assert payload.version >= 3
                        assert 1 in payload.streams
                        self.remote_user_agent = payload.useragent
                        print(payload.version, payload.useragent)
                        verack = packet.Verack()
                        self.write(verack)
                        addr = packet.Addr()
                        addr.addresses = self.peers.get_addresses()
                        self.write(addr)
                        hashes = self.om.get_hashes_for_send()
                        for i in range(0, len(hashes), 50000):
                            inv = packet.Inv()
                            inv.hashes = hashes[i:i+50000]
                            self.write(inv)
                        host, port = self.writer.get_extra_info('peername')
                        ip = ipaddress.ip_address(host)
                        if ip.version == 4:
                            self.remote_host = bytes.fromhex('00000000000000000000ffff')+ip.packed
                        else:
                            self.remote_host = ip.packed
                        self.remote_port = version.src_port

                        for func in self.on_connect:
                            func()
                        self.got_version = True
                if not self.got_verack:
                    if header.command == 'verack':
                        payload = packet.Verack(payloaddata)
                        self.got_verack = True
                if self.got_version and self.got_verack:
                    if header.command == 'addr':
                        addr = packet.Addr(payloaddata)
                        for address in addr.addresses:
                            self.peers.add(address)
                    elif header.command == 'inv':
                        inv = packet.Inv(payloaddata)
                        getdata = packet.Getdata()
                        for hash in inv.hashes:
                            object = self.om.get_object(hash)
                            if object is None:
                                getdata.hashes.append(hash)
                        if len(getdata.hashes) > 0:
                            self.write(getdata)
                    elif header.command == 'getdata':
                        getdata = packet.Getdata(payloaddata)
                        for hash in getdata.hashes:
                            object = self.om.get_object(hash)
                            if object is not None:
                                self.write(object)
                                yield from self.writer.drain()
                    elif header.command == 'object':
                        object = packet.Object(payloaddata)
                        self.om.add_object(object)
                        #print(object.nonce, object.expires, object.type, object.version, object.stream, binascii.hexlify( object.payload))
                #print(self.om.count(), 'objects stored')
                #print(self.peers.count(), 'known peers')
                #print(len(self.peers.connections), 'conns')
                yield from self.writer.drain()
        except:
            for func in self.on_disconnect:
                func()

    def _on_add_object(self, object):
        if self.got_version:
            inv = packet.Inv()
            inv.hashes.append(object.hash)
            self.write(inv)



