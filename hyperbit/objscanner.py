# Copyright 2015-2016 HyperBit developers

import asyncio
import logging
import time


logger = logging.getLogger(__name__)


class Scanner():
    def __init__(self, db, inv, wal):
        logger.debug('start')
        self._db = db
        self._db.execute(
            'CREATE TABLE IF NOT EXISTS scans'
            ' (hash, address, unique(hash, address))')
        self._index = 0
        for count, in self._db.execute('SELECT count(*) FROM scans'):
            self._count = count
        self._inv = inv
        self._wal = wal
        self.on_change = []
        self.on_scan_item = []
        if self._count > 0:
            asyncio.get_event_loop().create_task(self._run())

    def scan(self, invhash, identity):
        address = (
            b'' if identity is None else identity.profile.address.to_bytes())
        if self._count == 0:
            asyncio.get_event_loop().create_task(self._run())
        self._count += self._db.execute(
            'INSERT INTO scans (hash, address) VALUES (?, ?)',
            (invhash, address)
        ).rowcount

    @asyncio.coroutine
    def _run(self):
        last = time.time()
        for func in self.on_change:
            func()
        while self._index < self._count:
            # for count, in self._db.execute('select count(*) from scans'):
            #     print(self._index, self._count, count)
            for invhash, address, rowid in self._db.execute(
                    'SELECT hash, address, rowid FROM scans LIMIT 1'):
                self._db.execute('DELETE FROM scans WHERE rowid = ?', (rowid,))
                obj = self._inv.get_object(invhash)
                for identity2 in self._wal.identities:
                    if identity2.profile.address.to_bytes() == address:
                        identity = identity2
                        break
                else:
                    identity = None
                for func in self.on_scan_item:
                    func(obj, identity)
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
