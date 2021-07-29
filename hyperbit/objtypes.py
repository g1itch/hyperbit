# Copyright 2015-2016 HyperBit developers
# pylint: disable=too-many-arguments,too-many-instance-attributes

import enum

from hyperbit import crypto, serialize


class Type(enum.IntEnum):
    getpubkey = 0
    pubkey = 1
    msg = 2
    broadcast = 3
    onionpeer = 0x746f72


class Onionpeer():
    def __init__(self, stream, version, host, port):
        self.stream = stream
        self.version = version
        self.host = host
        self.port = port

    @classmethod
    def from_bytes(cls, data):
        s = serialize.Deserializer(data)
        # this is strange, looks like a bug in PyBitmessage
        data = s.bytes(2)
        if data == b'\xfd\x20':
            version = 3
        else:
            version = 2
        # this is not gonna work before the bug is got fixed
        # port = int.from_bytes(data, 'little', signed=False)
        port = 8444
        stream = 1
        # version = s.vint()
        # stream = s.vint()
        # port = s.vint()
        host = s.vbytes()
        return cls(stream, version, host, port)

    def to_bytes(self):
        s = serialize.Serializer()
        s.data += self.port.to_bytes(self.version, 'little', signed=False)
        s.vbytes(self.host)
        return s.data


class Getpubkey23():
    def __init__(self, ripe):
        self.ripe = ripe

    @classmethod
    def from_bytes(cls, data):
        return cls(data)

    def to_bytes(self):
        return self.ripe


class Getpubkey4():
    def __init__(self, tag):
        self.tag = tag

    @classmethod
    def from_bytes(cls, data):
        return cls(data)

    def to_bytes(self):
        return self.tag


class Pubkey2():
    def __init__(self, behavior, verkey, enckey):
        self.behavior = behavior
        self.verkey = verkey
        self.enckey = enckey

    @classmethod
    def from_bytes(cls, data):
        return cls(int.from_bytes(data[:4], 'big'), data[4:68], data[68:132])

    def to_bytes(self):
        return self.behavior.to_bytes(4, 'big') + self.verkey + self.enckey


class Pubkey3():
    def __init__(self, behavior, verkey, enckey, trials, extra, signature):
        self.behavior = behavior
        self.verkey = verkey
        self.enckey = enckey
        self.trials = trials
        self.extra = extra
        self.signature = signature

    @classmethod
    def from_bytes(cls, data):
        s = serialize.Deserializer(data)
        behavior = s.uint(4)
        verkey = s.bytes(64)
        enckey = s.bytes(64)
        trials = s.vint()
        extra = s.vint()
        signature = s.vbytes()
        return cls(behavior, verkey, enckey, trials, extra, signature)

    def to_bytes(self):
        s = serialize.Serializer()
        s.uint(self.behavior, 4)
        s.bytes(self.verkey)
        s.bytes(self.enckey)
        s.vint(self.trials)
        s.vint(self.extra)
        s.vbytes(self.signature)
        return s.data


class Pubkey4():
    def __init__(self, tag, encrypted):
        assert len(tag) == 32
        self.tag = tag
        self.encrypted = encrypted

    @classmethod
    def from_bytes(cls, data):
        return cls(data[:32], data[32:])

    def to_bytes(self):
        return self.tag + self.encrypted


class Msg1():
    def __init__(self, encrypted):
        self.encrypted = encrypted

    @classmethod
    def from_bytes(cls, data):
        return cls(data)

    def to_bytes(self):
        return self.encrypted


class Broadcast4():
    def __init__(self, encrypted):
        self.encrypted = encrypted

    @classmethod
    def from_bytes(cls, data):
        return cls(data)

    def to_bytes(self):
        return self.encrypted


class Broadcast5():
    def __init__(self, tag, encrypted):
        assert len(tag) == 32
        self.tag = tag
        self.encrypted = encrypted

    @classmethod
    def from_bytes(cls, data):
        return cls(data[:32], data[32:])

    def to_bytes(self):
        return self.tag + self.encrypted


class MsgData():
    def __init__(
        self, addrver, stream, behavior, verkey, enckey, trials, extra,
        ripe, encoding, message, ack, signature
    ):
        self.addrver = addrver
        self.stream = stream
        self.behavior = behavior
        self.verkey = verkey
        self.enckey = enckey
        self.trials = trials
        self.extra = extra
        self.ripe = ripe
        self.encoding = encoding
        self.message = message
        self.ack = ack
        self.signature = signature

    @classmethod
    def from_bytes(cls, data):
        s = serialize.Deserializer(data)
        addrver = s.vint()
        stream = s.vint()
        behavior = s.uint(4)
        verkey = s.bytes(64)
        enckey = s.bytes(64)
        trials = s.vint()
        extra = s.vint()
        ripe = s.bytes(20)
        encoding = s.vint()
        message = s.vbytes()
        ack = s.vbytes()
        signature = s.vbytes()
        return cls(
            addrver, stream, behavior, verkey, enckey, trials, extra, ripe,
            encoding, message, ack, signature)

    def to_bytes(self):
        s = serialize.Serializer()
        s.vint(self.addrver)
        s.vint(self.stream)
        s.uint(self.behavior, 4)
        s.bytes(self.verkey)
        s.bytes(self.enckey)
        s.vint(self.trials)
        s.vint(self.extra)
        s.bytes(self.ripe)
        s.vint(self.encoding)
        s.vbytes(self.message)
        s.vbytes(self.ack)
        s.vbytes(self.signature)
        return s.data

    def sign(self, sigkey, obj):
        s = serialize.Serializer()
        s.uint(obj.expires, 8)
        s.uint(obj.type, 4)
        s.vint(obj.version)
        s.vint(obj.stream)
        s.vint(self.addrver)
        s.vint(self.stream)
        s.uint(self.behavior, 4)
        s.bytes(self.verkey)
        s.bytes(self.enckey)
        s.vint(self.trials)
        s.vint(self.extra)
        s.bytes(self.ripe)
        s.vint(self.encoding)
        s.vbytes(self.message)
        s.vbytes(self.ack)
        self.signature = crypto.sign(sigkey, s.data)

    def verify(self, obj):
        s = serialize.Serializer()
        s.uint(obj.expires, 8)
        s.uint(obj.type, 4)
        s.vint(obj.version)
        s.vint(obj.stream)
        s.vint(self.addrver)
        s.vint(self.stream)
        s.uint(self.behavior, 4)
        s.bytes(self.verkey)
        s.bytes(self.enckey)
        s.vint(self.trials)
        s.vint(self.extra)
        s.bytes(self.ripe)
        s.vint(self.encoding)
        s.vbytes(self.message)
        s.vbytes(self.ack)
        crypto.verify(self.verkey, s.data, self.signature)


class BroadcastData():
    def __init__(
        self, addrver, stream, behavior, verkey, enckey, trials, extra,
        encoding, message, signature
    ):
        self.addrver = addrver
        self.stream = stream
        self.behavior = behavior
        self.verkey = verkey
        self.enckey = enckey
        self.trials = trials
        self.extra = extra
        self.encoding = encoding
        self.message = message
        self.signature = signature

    @classmethod
    def from_bytes(cls, data):
        s = serialize.Deserializer(data)
        addrver = s.vint()
        stream = s.vint()
        behavior = s.uint(4)
        verkey = s.bytes(64)
        enckey = s.bytes(64)
        trials = s.vint()
        extra = s.vint()
        encoding = s.vint()
        message = s.vbytes()
        signature = s.vbytes()
        return cls(
            addrver, stream, behavior, verkey, enckey, trials, extra, encoding,
            message, signature)


class Encoding(enum.IntEnum):
    ignore = 0
    trivial = 1
    simple = 2


class SimpleMessage():
    encoding = Encoding.simple

    def __init__(self, subject, body):
        self.subject = subject
        self.body = body

    @classmethod
    def from_bytes(cls, data):
        text = data.decode(errors='replace')
        try:
            subject = text[8:text.index('\n')]
        except Exception:  # TODO: exception type
            subject = ''
        try:
            body = text[text.index('\nBody:')+6:]
        except ValueError:
            body = text
        return cls(subject, body)

    def to_bytes(self):
        return ('Subject:' + self.subject + '\nBody:' + self.body).encode()
