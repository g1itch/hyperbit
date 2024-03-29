# Copyright 2015-2016 HyperBit developers

import enum
import logging

from hyperbit import base58, serialize, crypto, config

logger = logging.getLogger(__name__)


class IdentityType(enum.IntEnum):
    normal = 0
    channel = 1


class Address():
    def __init__(self, version, stream, ripe):
        self.version = version
        self.stream = stream
        self.ripe = ripe
        sha = crypto.sha512d(self.to_bytes())
        self.xkey = sha[0:32]
        self.tag = sha[32:64]

    @classmethod
    def from_str(cls, text):
        data = base58.decode(text)
        s = serialize.Deserializer(data)
        version = s.vint()
        stream = s.vint()
        ripe = s.bytes().rjust(20, b'\x00')
        return cls(version, stream, ripe)

    def to_str(self):
        s = serialize.Serializer()
        s.vint(self.version)
        s.vint(self.stream)
        s.bytes(self.ripe.lstrip(b'\x00'))
        return base58.encode(s.data)

    @classmethod
    def from_bytes(cls, data):
        s = serialize.Deserializer(data)
        version = s.vint()
        stream = s.vint()
        ripe = s.bytes(20)
        return cls(version, stream, ripe)

    def to_bytes(self):
        s = serialize.Serializer()
        s.vint(self.version)
        s.vint(self.stream)
        s.bytes(self.ripe)
        return s.data


class Profile2():
    def __init__(self, db, address):
        self._db = db
        self._address = address

    @property
    def address(self):
        return self._address

    @property
    def name(self):
        for name, in self._db.execute(
                'SELECT name FROM profiles WHERE address = ?',
                (self._address.to_bytes(),)):
            return name

    @property
    def verkey(self):
        for verkey, in self._db.execute(
                'SELECT verkey FROM profiles WHERE address = ?',
                (self._address.to_bytes(),)):
            return verkey[-64:]

    @property
    def enckey(self):
        for enckey, in self._db.execute(
                'SELECT enckey FROM profiles WHERE address = ?',
                (self._address.to_bytes(),)):
            return enckey[-64:]

    def encrypt(self, data):
        return crypto.encrypt(self.enckey, data)

    def verify(self, data, signature):
        crypto.verify(self.verkey, data, signature)


class Identity2():
    def __init__(self, db, address):
        self._db = db
        self._address = address

    @property
    def address(self):
        return self._address

    @property
    def profile(self):
        return Profile2(self._db, self._address)

    @property
    def type(self):
        for name, in self._db.execute(
                'SELECT name FROM identities WHERE address = ?',
                (self._address.to_bytes(),)):
            return name

    @type.setter
    def type(self, value):
        self._db.execute(
            'UPDATE identities SET name = ? WHERE address = ?',
            (value, self._address.to_bytes(),))

    @property
    def sigkey(self):
        for sigkey, in self._db.execute(
                'SELECT sigkey FROM identities WHERE address = ?',
                (self._address.to_bytes(),)):
            return sigkey

    @property
    def deckey(self):
        for deckey, in self._db.execute(
                'SELECT deckey FROM identities WHERE address = ?',
                (self._address.to_bytes(),)):
            return deckey

    def sign(self, data):
        return crypto.sign(self.sigkey, data)

    def decrypt(self, data):
        return crypto.decrypt(self.deckey, data)

    def __eq__(self, other):
        if isinstance(other, Identity2):
            return (
                self._db == other._db
                and self._address.to_bytes() == other._address.to_bytes())

        return NotImplemented


class Wallet():
    def __init__(self, db):
        logger.debug('start')
        self._db = db
        self._db.execute(
            'CREATE TABLE IF NOT EXISTS identities'
            ' (address unique, name, sigkey, deckey)')
        self._db.execute(
            'CREATE TABLE IF NOT EXISTS profiles'
            ' (address unique, name, verkey, enckey)')
        self.on_add_identity = []
        self.on_remove_identity = []
        self.names = Names(self._db)

        for identity in self.identities:
            if isinstance(identity.type, str):
                identity.type = (
                    1 if self.names.get(
                        identity.profile.address.ripe)[0:6] == '[chan]'
                    else 0)

    def new_deterministic(self, name, type, text):
        for i in range(0, 2**64, 2):
            s1 = serialize.Serializer()
            s1.str(text)
            s1.vint(i)
            sigkey = crypto.sha512(s1.data)[0:32]
            s2 = serialize.Serializer()
            s2.str(text)
            s2.vint(i + 1)
            deckey = crypto.sha512(s2.data)[0:32]
            verkey = crypto.priv_to_pub(sigkey)
            enckey = crypto.priv_to_pub(deckey)
            ripe = crypto.to_ripe(verkey, enckey)
            if ripe[0:1] == b'\x00':
                return self.new_identity(name, type, sigkey, deckey)

    def new_random(self, name, type):
        sigkey = crypto.gen_priv()
        deckey = crypto.gen_priv()
        return self.new_identity(name, type, sigkey, deckey)

    def new_identity(self, name, type, sigkey, deckey):
        verkey = crypto.priv_to_pub(sigkey)
        enckey = crypto.priv_to_pub(deckey)
        ripe = crypto.to_ripe(verkey, enckey)
        self.names.set(ripe, name)
        address = Address(4, config.NETWORK_STREAM, ripe)
        self._db.execute(
            'INSERT INTO identities (address, name, sigkey, deckey)'
            ' VALUES (?, ?, ?, ?)', (address.to_bytes(), type, sigkey, deckey))
        self._db.execute(
            'INSERT INTO profiles (address, name, verkey, enckey)'
            ' VALUES (?, ?, ?, ?)',
            (address.to_bytes(), type, b'\x04' + verkey, b'\x04' + enckey))
        identity = Identity2(self._db, address)
        for func in self.on_add_identity:
            func(identity)
        return identity

    def get_identity(self, address):
        return Identity2(self._db, Address.from_bytes(address))

    @property
    def identities(self):
        identities = []
        for address, in self._db.execute('SELECT address FROM identities'):
            identities.append(Identity2(self._db, Address.from_bytes(address)))
        return identities

    @property
    def profiles(self):
        profiles = []
        for address, in self._db.execute('SELECT address FROM profiles'):
            profiles.append(Profile2(self._db, Address.from_bytes(address)))
        return profiles

    def remove_identity(self, identity):
        for func in self.on_remove_identity:
            func(identity)
        self._db.execute(
            'DELETE FROM identities WHERE address = ?',
            (identity.address.to_bytes(),))
        self._db.execute(
            'DELETE FROM profiles WHERE address = ?',
            (identity.address.to_bytes(),))


class Names():
    def __init__(self, db):
        self._db = db
        if not self._db.execute(
                'SELECT 1 FROM sqlite_master WHERE name = "names"').fetchone():
            self._db.execute('CREATE TABLE names (ripe unique, name)')
            self._db.execute(
                'INSERT INTO names (ripe, name)'
                ' SELECT substr(address, 3), name FROM identities')
        self._on_changed = dict()
        self._on_changed_all = list()

    def on_changed_add(self, ripe, callback):
        if ripe not in self._on_changed:
            self._on_changed[ripe] = list()
        self._on_changed[ripe].append(callback)

    def on_changed_remove(self, ripe, callback):
        self._on_changed[ripe].remove(callback)
        if not self._on_changed[ripe]:
            del self._on_changed[ripe]

    def on_changed_all_add(self, callback):
        self._on_changed_all.append(callback)

    def on_changed_all_remove(self, callback):
        self._on_changed_all.remove(callback)

    def set(self, ripe, name):
        if (
            not name
            or name == Address(4, config.NETWORK_STREAM, ripe).to_str()
        ):
            self._db.execute('DELETE FROM names WHERE ripe = ?', (ripe,))
        else:
            self._db.execute(
                'REPLACE INTO names (ripe, name) VALUES (?, ?)', (ripe, name))
        if ripe in self._on_changed:
            for func in self._on_changed[ripe]:
                func()
        for func in self._on_changed_all:
            func()

    def get(self, ripe):
        row = self._db.execute(
            'SELECT name FROM names WHERE ripe = ?', (ripe,)).fetchone()
        if row:
            return row[0]

        return Address(4, config.NETWORK_STREAM, ripe).to_str()
