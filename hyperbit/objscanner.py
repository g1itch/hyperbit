# Copyright 2015 HyperBit developers

import asyncio
import collections
import time
from hyperbit import database


class Scanner(object):
    def __init__(self, inv, wal):
        database.db2.execute('create table if not exists scans (hash, address, unique(hash, address))')
        self._index = 0
        for count, in database.db2.execute('select count(*) from scans'):
            self._count = count
        self._inv = inv
        self._wal = wal
        self.on_change = []
        self.on_scan_item = []
        if self._count > 0:
            asyncio.get_event_loop().create_task(self._run())

    def scan(self, hash, identity):
        address = b'' if identity is None else identity.profile.address.to_bytes()
        if self._count == 0:
            asyncio.get_event_loop().create_task(self._run())
        self._count += database.db2.execute('insert into scans (hash, address) values (?, ?)', (hash, address)).rowcount

    @asyncio.coroutine
    def _run(self):
        last = time.time()
        for func in self.on_change:
            func()
        while self._index < self._count:
            #for count, in database.db2.execute('select count(*) from scans'):
            #    print(self._index, self._count, count)
            for hash, address, rowid in database.db2.execute('select hash, address, rowid from scans limit 1'):
                database.db2.execute('delete from scans where rowid = ?', (rowid,))
                object = self._inv.get_object(hash)
                for identity2 in self._wal.identities:
                    if identity2.profile.address.to_bytes() == address:
                        identity = identity2
                        break
                else:
                    identity = None
                for func in self.on_scan_item:
                    func(object, identity)
                self._index += 1
                if time.time() >= last + 0.1:
                    last = time.time()
                    for func in self.on_change:
                        func()
                yield
        self._index = 0
        self._count = 0
        for func in self.on_change:
            func()

    @property
    def value(self):
        return self._index

    @property
    def max(self):
        return self._count

