# Copyright 2015 HyperBit developers

import asyncio, pickle, time

from hyperbit import config, objtypes, packet


class Inventory(object):
    def __init__(self, db):
        self._db = db
        self._db.execute('create table if not exists objects (hash unique, brink, expires, data)')
        self.on_add_object = []
        self.on_remove_object = []
        asyncio.get_event_loop().call_soon(self._cleanup)
        self.on_stats_changed = []

    def _cleanup(self):
        for hash, data in self._db.execute('select hash, data from objects where expires < ?', (int(time.time())-3*60*60,)):
            object = packet.Object(data)
            for func in self.on_remove_object:
                func(object)
            self._db.execute('delete from objects where hash = ?', (hash,))
        for func in self.on_stats_changed:
            func()
        asyncio.get_event_loop().call_later(config.CLEANUP_INTERVAL, self._cleanup)

    def get_object(self, hash):
        for data, in self._db.execute('select data from objects where hash = ?', (hash,)):
            object = packet.Object(data)
            return object

    def add_object(self, object):
        exists = self._db.execute('select count(*) from objects where hash = ?', (object.hash,)).fetchone()[0]
        if exists:
            return
        now = int(time.time())
        start = now
        end = now+28*24*60*60
        margin = 3*60*60
        if object.check_pow(config.NETWORK_TRIALS, config.NETWORK_EXTRA, start+margin) and start-margin <= object.expires <= end+margin:
            self._db.execute('insert into objects (hash, brink, expires, data) values (?, ?, ?, ?)',
                    (object.hash, object.brink, object.expires, object.data))
            for func in self.on_add_object:
                func(object)
        for func in self.on_stats_changed:
            func()

    def count(self):
        for count, in self._db.execute('select count(*) from objects'):
            return count

    def get_hashes(self):
        hashes = []
        for hash, in self._db.execute('select hash from objects order by hash'):
            hashes.append(hash)
        return hashes

    #FIXME When objects are added before they are officially
    #FIXME valid they should not be sent until they are.
    #FIXME This is quite complicated to implement though
    #FIXME and not implementing it should not have any
    #FIXME major effects.
    def get_hashes_for_send(self):
        hashes = []
        now = int(time.time())
        start = now-28*24*60*60
        end = now
        for hash, in self._db.execute('select hash from objects where ? <= expires and expires <= ? order by hash', (start, end)):
            hashes.append(hash)
        return hashes
