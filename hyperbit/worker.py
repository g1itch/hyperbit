# Copyright 2015-2016 HyperBit developers

import asyncio
import concurrent.futures
import logging

from hyperbit import packet, pow

logger = logging.getLogger(__name__)


class Worker():
    """A worker that can compute object POWs"""
    def __init__(self, db):
        """Worker that can compute object PoWs."""
        logger.debug('start')
        self._db = db
        self._db.execute(
            'CREATE TABLE IF NOT EXISTS worker (obj, trials, extra, timestamp)'
        )
        self._executor = concurrent.futures.ProcessPoolExecutor()
        for obj, trials, extra, timestamp in self._db.execute(
                'SELECT * FROM worker'):
            asyncio.get_event_loop().create_task(self._run(
                packet.Object.from_bytes(obj), trials, extra, timestamp))
        self.on_object_done = []
        """Called with an object when its POW has been computed."""

    @asyncio.coroutine
    def _run(self, obj, trials, extra, timestamp):
        ttl = int(obj.expires - timestamp)
        data = obj.data[8:]
        # length = len(data) + 8 + extra
        loop = asyncio.get_event_loop()
        self._db.execute(
            'INSERT INTO worker VALUES (?, ?, ?, ?)',
            (obj.data, trials, extra, timestamp))
        nonce = yield from loop.run_in_executor(
            self._executor, pow.pow, data, trials, extra, ttl)
        self._db.execute('DELETE FROM worker WHERE obj = ?', (obj.data,))
        obj.nonce = nonce
        for func in self.on_object_done:
            func(obj)

        logger.info('object nonce computed')

    def add_object(self, obj, trials, extra, timestamp):
        """Queue an object for POW computation."""
        logger.info('compute nonce for object of length %s', len(obj.data))
        asyncio.get_event_loop().create_task(self._run(
            obj, trials, extra, timestamp))
