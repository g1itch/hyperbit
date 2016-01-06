# Copyright 2015-2016 HyperBit developers

import asyncio
import logging
import time

from hyperbit import config, packet

logger = logging.getLogger(__name__)


class Inventory():
    def __init__(self, db):
        logger.info('start')
        self._db = db
        self._db.execute(
            'CREATE TABLE IF NOT EXISTS objects'
            ' (hash unique, brink, expires, data)')
        self.on_add_object = []
        self.on_remove_object = []
        asyncio.get_event_loop().call_soon(self._cleanup)
        self.on_stats_changed = []

    def _cleanup(self):
        for invhash, data in self._db.execute(
            'SELECT hash, data FROM objects WHERE expires < ?',
            (int(time.time()) - 3 * 60 * 60,)
        ):
            obj = packet.Object.from_bytes(data)
            for func in self.on_remove_object:
                func(obj)
            self._db.execute('DELETE FROM objects WHERE hash = ?', (invhash,))
        for func in self.on_stats_changed:
            func()
        asyncio.get_event_loop().call_later(
            config.CLEANUP_INTERVAL, self._cleanup)

    def get_object(self, invhash):
        for data, in self._db.execute(
                'SELECT data FROM objects WHERE hash = ?', (invhash,)):
            return packet.Object.from_bytes(data)

    def add_object(self, obj):
        exists = self._db.execute(
            'SELECT count(*) FROM objects WHERE hash = ?', (obj.hash,)
        ).fetchone()[0]
        if exists:
            return
        now = int(time.time())
        start = now
        end = now + 28 * 24 * 60 * 60
        margin = 3 * 60 * 60
        if (
            obj.check_pow(
                config.NETWORK_TRIALS, config.NETWORK_EXTRA, start + margin)
            and start - margin <= obj.expires <= end + margin
        ):
            self._db.execute(
                'INSERT INTO objects (hash, brink, expires, data)'
                ' VALUES (?, ?, ?, ?)',
                (obj.hash, obj.brink, obj.expires, obj.data))
            for func in self.on_add_object:
                func(obj)
        for func in self.on_stats_changed:
            func()

    def count(self):
        for count, in self._db.execute('SELECT count(*) FROM objects'):
            return count

    def get_hashes(self):
        hashes = []
        for invhash, in self._db.execute(
                'SELECT hash FROM objects ORDER BY hash'):
            hashes.append(invhash)
        return hashes

    # FIXME:
    # ! When objects are added before they are officially
    # ! valid they should not be sent until they are.
    # ! This is quite complicated to implement though
    # ! and not implementing it should not have any
    # ! major effects.
    def get_hashes_for_send(self):
        hashes = []
        now = int(time.time())
        start = now - 28 * 24 * 60 * 60
        end = now
        for invhash, in self._db.execute(
            'SELECT hash FROM objects WHERE ? <= expires AND expires <= ?'
            ' ORDER BY hash', (start, end)
        ):
            hashes.append(invhash)
        return hashes
