# Copyright 2015 HyperBit developers
import collections
import random
import time
from hyperbit import config, pow, serialize, crypto

class Header(object):
    def __init__(self, data=None):
        if data is None:
            self.magic = 0xe9beb4d9
            self.command = ''
            self.length = 0
            self.checksum = bytes.fromhex('cf83e135')
        else:
            s = serialize.Deserializer(data)
            self.magic = s.uint(4)
            self.command = s.str(12).rstrip('\0')
            self.length = s.uint(4)
            self.checksum = s.bytes(4)

    @property
    def data(self):
        s = serialize.Serializer()
        s.uint(self.magic, 4)
        s.bytes(bytes(self.command, 'utf8')[:12].ljust(12, b'\0'))
        s.uint(self.length, 4)
        s.bytes(self.checksum)
        return s.data


class Version(object):
    def __init__(self, data=None):
        self.command = 'version'
        if data is None:
            self.version = 3
            self.services = 1 # NODE_NETWORK
            self.timestamp = int(time.time())
            self.dst_services = 1
            self.dst_ip = (0).to_bytes(16, byteorder='big')
            self.dst_port = 8444
            self.src_services = 1
            self.src_ip = (0).to_bytes(16, byteorder='big')
            self.src_port = 8444
            self.nonce = 0
            self.useragent = ''
            self.streams = [1]
        else:
            s = serialize.Deserializer(data)
            self.version = s.uint(4)
            self.services = s.uint(8)
            self.timestamp = s.uint(8)
            self.dst_services = s.uint(8)
            self.dst_ip = s.bytes(16)
            self.dst_port = s.uint(2)
            self.src_services = s.uint(8)
            self.src_ip = s.bytes(16)
            self.src_port = s.uint(2)
            self.nonce = s.uint(8)
            self.useragent = s.vstr()
            self.streams = []
            for i in range(s.vint()):
                self.streams.append(s.vint())

    @property
    def data(self):
        t = serialize.Serializer()
        t.uint(self.version, 4)
        t.uint(self.services, 8)
        t.uint(self.timestamp, 8)
        t.uint(self.dst_services, 8)
        t.bytes(self.dst_ip)
        t.uint(self.dst_port, 2)
        t.uint(self.src_services, 8)
        t.bytes(self.src_ip)
        t.uint(self.src_port, 2)
        t.uint(self.nonce, 8)
        t.vstr(self.useragent)
        t.vint(len(self.streams))
        for stream in self.streams:
            t.vint(stream)
        return t.data


class Verack(object):
    def __init__(self, data=None):
        self.command = 'verack'

    @property
    def data(self):
        return b''

Address = collections.namedtuple('Address', ['time', 'stream', 'services', 'ip', 'port'])
Endpoint = collections.namedtuple('Endpoint', ['ip', 'port'])

class Addr(object):
    def __init__(self, data=None):
        self.command = 'addr'
        self.addresses = []
        if data is not None:
            s = serialize.Deserializer(data)
            for i in range(s.vint()):
                time = s.uint(8)
                stream = s.uint(4)
                services = s.uint(8)
                ip = s.bytes(16)
                port = s.uint(2)
                self.addresses.append(Address(time, stream, services, ip, port))

    @property
    def data(self):
        s = serialize.Serializer()
        s.vint(len(self.addresses))
        for address in self.addresses:
            s.uint(address.time, 8)
            s.uint(address.stream, 4)
            s.uint(address.services, 8)
            s.bytes(address.ip)
            s.uint(address.port, 2)
        return s.data


class Inv(object):
    def __init__(self, data=None):
        self.command = 'inv'
        self.hashes = []
        if data is not None:
            s = serialize.Deserializer(data)
            for i in range(s.vint()):
                self.hashes.append(s.bytes(32))

    @property
    def data(self):
        s = serialize.Serializer()
        s.vint(len(self.hashes))
        for hash in self.hashes:
            s.bytes(hash)
        return s.data


class Getdata(object):
    def __init__(self, data=None):
        self.command = 'getdata'
        self.hashes = []
        if data is not None:
            s = serialize.Deserializer(data)
            for i in range(s.vint()):
                self.hashes.append(s.bytes(32))

    @property
    def data(self):
        s = serialize.Serializer()
        s.vint(len(self.hashes))
        for hash in self.hashes:
            s.bytes(hash)
        return s.data


class Object(object):
    def __init__(self, data=None):
        self.command = 'object'
        if data is None:
            self.nonce = 0
            self.expires = int(time.time() + 4 * 24 * 60 * 60) # FIXME add some random time too
            self.type = 0
            self.version = 0
            self.stream = 1
            self.payload = b''
        else:
            s = serialize.Deserializer(data)
            self.nonce = s.uint(8)
            self.expires = s.uint(8)
            self.type = s.uint(4)
            self.version = s.vint()
            self.stream = s.vint()
            self.payload = s.data

    @property
    def hash(self):
        return crypto.sha512d(self.data)[:32]

    @property
    def brink(self):
        a = self.nonce.to_bytes(8, 'big')
        initial = crypto.sha512(self.data[8:])
        c = crypto.sha512d(a+initial)
        value = int.from_bytes(c[:8], 'big')
        return int(self.expires-2**80/(value*config.NETWORK_TRIALS*(len(self.data)+config.NETWORK_EXTRA))+2**16)

    @property
    def valid(self):
        ttl = int(self.expires - time.time())
        completed = pow.check(self.data[8:], config.NETWORK_TRIALS, config.NETWORK_EXTRA, ttl, self.nonce)
        unexpired = ttl > 0
        return completed and unexpired

    def check_expiration(self, timestamp):
        return timestamp <= self.expires

    def check_pow(self, trials, extra, timestamp):
        ttl = int(self.expires - timestamp)
        completed = pow.check(self.data[8:], trials, extra, ttl, self.nonce)
        return completed

    def do_pow(self, trials, extra, timestamp):
        ttl = int(self.expires - timestamp)
        self.nonce = pow.pow(self.data[8:], trials, extra, ttl)

    def complete(self):
        ttl = int(self.expires - time.time())
        self.nonce = yield from pow.wrapper(self.data[8:], config.NETWORK_TRIALS, config.NETWORK_EXTRA, ttl)

    @property
    def data(self):
        s = serialize.Serializer()
        s.uint(self.nonce, 8)
        s.uint(self.expires, 8)
        s.uint(self.type, 4)
        s.vint(self.version)
        s.vint(self.stream)
        s.bytes(self.payload)
        return s.data
