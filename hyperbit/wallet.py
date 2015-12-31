# Copyright 2015 HyperBit developers

from hyperbit import base58, serialize, crypto, database


class Address(object):
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
        ripe = s.data.rjust(20, b'\x00')
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


class Profile2(object):
    def __init__(self, address):
        self._address = address

    @property
    def address(self):
        return self._address

    @property
    def name(self):
        for name, in database.db2.execute('select name from profiles where address = ?', (self._address.to_bytes(),)):
            return name

    @property
    def verkey(self):
        for verkey, in database.db2.execute('select verkey from profiles where address = ?', (self._address.to_bytes(),)):
            return verkey

    @property
    def enckey(self):
        for enckey, in database.db2.execute('select enckey from profiles where address = ?', (self._address.to_bytes(),)):
            return enckey

    def encrypt(self, data):
        return crypto.encrypt(self.enckey, data)

    def verify(self, data, signature):
        crypto.verify(self.verkey, data, signature)


class Identity2(object):
    def __init__(self, address):
        self._address = address

    @property
    def address(self):
        return self._address

    @property
    def profile(self):
        return Profile2(self._address)

    @property
    def name(self):
        for name, in database.db2.execute('select name from identities where address = ?', (self._address.to_bytes(),)):
            return name

    @property
    def sigkey(self):
        for sigkey, in database.db2.execute('select sigkey from identities where address = ?', (self._address.to_bytes(),)):
            return sigkey

    @property
    def deckey(self):
        for deckey, in database.db2.execute('select deckey from identities where address = ?', (self._address.to_bytes(),)):
            return deckey

    def sign(self, data):
        return crypto.sign(self.sigkey, data)

    def decrypt(self, data):
        return crypto.decrypt(self.deckey, data)


class Wallet(object):
    def __init__(self):
        database.db2.execute('create table if not exists identities (address unique, name, sigkey, deckey)')
        database.db2.execute('create table if not exists profiles (address unique, name, verkey, enckey)')
        self.on_add_identity = []
        self.on_remove_identity = []

    def new_deterministic(self, name, text):
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
            ripe = crypto.bm160(verkey + enckey)
            if ripe[0:1] == b'\x00':
                return self.new_identity(name, sigkey, deckey)

    def new_random(self, name):
        sigkey = crypto.gen_priv()
        deckey = crypto.gen_priv()
        return self.new_identity(name, sigkey, deckey)

    def new_identity(self, name, sigkey, deckey):
        verkey = crypto.priv_to_pub(sigkey)
        enckey = crypto.priv_to_pub(deckey)
        ripe = crypto.bm160(verkey + enckey)
        address = Address(4, 1, ripe)
        database.db2.execute('insert into identities (address, name, sigkey, deckey) values (?, ?, ?, ?)',
                (address.to_bytes(), name, sigkey, deckey))
        database.db2.execute('insert into profiles (address, name, verkey, enckey) values (?, ?, ?, ?)',
                (address.to_bytes(), name, verkey, enckey))
        identity = Identity2(address)
        for func in self.on_add_identity:
            func(identity)
        return identity

    def get_identity(self, address):
        return Identity2(Address.from_bytes(address))

    def add_identity(self, identity):
        address = identity.profile.address.to_bytes()
        database.db2.execute('insert into identities (address, name, sigkey, deckey) values (?, ?, ?, ?)',
                (address, identity.name, identity.deckey, identity.sigkey))
        profile = identity.profile
        database.db2.execute('insert into profiles (address, name, verkey, enckey) values (?, ?, ?, ?)',
                (address, '', profile.enckey, profile.verkey))
        self.identities.append(identity)
        for func in self.on_add_identity:
            func(identity)

    @property
    def identities(self):
        identities = []
        for address, in database.db2.execute('select address from identities order by name, address'):
            identities.append(Identity2(Address.from_bytes(address)))
        return identities

    @property
    def profiles(self):
        profiles = []
        for address, in database.db2.execute('select address from profiles order by name, address'):
            profiles.append(Profile2(Address.from_bytes(address)))
        return profiles


class AddressEntry(object):
    def __init__(self, name, address):
        self.name = name
        self.address = address

class AddressBook(object):
    def __init__(self):
        self.entries = []
        self.on_add_entry = []

    def add_entry(self,entry):
        self.entries.append(entry)
        for func in self.on_add_entry:
            func(entry)

class ProfileCache(object):
    def __init__(self):
        self.profiles = []
        self.on_add_profile = []

    def add_profile(self, profile):
        self.profiles.append(profile)
        for func in self.on_add_profile:
            func(profile)



