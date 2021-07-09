# Copyright 2015-2016 HyperBit developers

import collections
import time

from hyperbit import config, pow, serialize, crypto


class Header(object):
    def __init__(self, magic, command, length, checksum):
        self.magic = magic
        self.command = command
        self.length = length
        self.checksum = checksum

    @classmethod
    def from_bytes(cls, data):
        s = serialize.Deserializer(data)
        magic = s.uint(4)
        command = s.str(12).rstrip('\0')
        length = s.uint(4)
        checksum = s.bytes(4)
        return cls(magic, command, length, checksum)

    def to_bytes(self):
        s = serialize.Serializer()
        s.uint(self.magic, 4)
        s.bytes(bytes(self.command, 'utf8')[:12].ljust(12, b'\0'))
        s.uint(self.length, 4)
        s.bytes(self.checksum)
        return s.data


class Generic(object):
    def __init__(self, command, data):
        self.command = command
        self.data = data


class Version(object):
    def __init__(
        self, version, services, timestamp, dst_services, dst_ip, dst_port,
        src_services, src_ip, src_port, nonce, user_agent, streams
    ):
        self.command = 'version'
        self.version = version
        self.services = services
        self.timestamp = timestamp
        self.dst_services = dst_services
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_services = src_services
        self.src_ip = src_ip
        self.src_port = src_port
        self.nonce = nonce
        self.user_agent = user_agent
        self.streams = streams

    @classmethod
    def from_bytes(cls, data):
        s = serialize.Deserializer(data)
        return cls(
            version=s.uint(4),
            services=s.uint(8),
            timestamp=s.uint(8),
            dst_services=s.uint(8),
            dst_ip=s.bytes(16),
            dst_port=s.uint(2),
            src_services=s.uint(8),
            src_ip=s.bytes(16),
            src_port=s.uint(2),
            nonce=s.uint(8),
            user_agent=s.vstr(),
            streams=[s.vint() for i in range(s.vint())]
        )

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
        t.vstr(self.user_agent)
        t.vint(len(self.streams))
        for stream in self.streams:
            t.vint(stream)
        return t.data


class Verack(object):
    def __init__(self):
        self.command = 'verack'

    @classmethod
    def from_bytes(cls, data):
        return cls()

    @property
    def data(self):
        return b''


Address = collections.namedtuple(
    'Address', ['time', 'stream', 'services', 'ip', 'port'])
Endpoint = collections.namedtuple('Endpoint', ['ip', 'port'])


class Addr(object):
    def __init__(self, addresses):
        self.command = 'addr'
        self.addresses = addresses

    @classmethod
    def from_bytes(cls, data):
        s = serialize.Deserializer(data)
        addresses = []
        for i in range(s.vint()):
            time = s.uint(8)
            stream = s.uint(4)
            services = s.uint(8)
            ip = s.bytes(16)
            port = s.uint(2)
            addresses.append(Address(time, stream, services, ip, port))
        return cls(addresses)

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
    def __init__(self, hashes):
        self.command = 'inv'
        self.hashes = hashes

    @classmethod
    def from_bytes(cls, data):
        s = serialize.Deserializer(data)
        return cls(
            hashes=[s.bytes(32) for i in range(s.vint())]
        )

    @property
    def data(self):
        s = serialize.Serializer()
        s.vint(len(self.hashes))
        for h in self.hashes:
            s.bytes(h)
        return s.data


class Getdata(object):
    def __init__(self, hashes):
        self.command = 'getdata'
        self.hashes = hashes

    @classmethod
    def from_bytes(cls, data):
        s = serialize.Deserializer(data)
        return cls(
            hashes=[s.bytes(32) for i in range(s.vint())]
        )

    @property
    def data(self):
        s = serialize.Serializer()
        s.vint(len(self.hashes))
        for h in self.hashes:
            s.bytes(h)
        return s.data


class Object(object):
    def __init__(self, nonce, expires, type, version, stream, payload):
        self.command = 'object'
        self.nonce = nonce
        self.expires = expires
        self.type = type
        self.version = version
        self.stream = stream
        self.payload = payload

    @classmethod
    def from_bytes(cls, data):
        s = serialize.Deserializer(data)
        return cls(
            nonce=s.uint(8),
            expires=s.uint(8),
            type=s.uint(4),
            version=s.vint(),
            stream=s.vint(),
            payload=s.bytes()
        )

    @property
    def hash(self):
        return crypto.sha512d(self.data)[:32]

    @property
    def brink(self):
        a = self.nonce.to_bytes(8, 'big')
        initial = crypto.sha512(self.data[8:])
        c = crypto.sha512d(a + initial)
        value = int.from_bytes(c[:8], 'big')
        return int(
            self.expires - 2**80 / (
                value * config.NETWORK_TRIALS * (
                    len(self.data) + config.NETWORK_EXTRA)
                ) + 2**16)

    @property
    def valid(self):
        ttl = int(self.expires - time.time())
        completed = pow.check(
            self.data[8:], config.NETWORK_TRIALS, config.NETWORK_EXTRA,
            ttl, self.nonce)
        unexpired = ttl > 0
        return completed and unexpired

    def check_expiration(self, timestamp):
        return timestamp <= self.expires

    def check_pow(self, trials, extra, timestamp):
        ttl = int(self.expires - timestamp)
        return pow.check(self.data[8:], trials, extra, ttl, self.nonce)

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
