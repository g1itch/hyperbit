# Copyright 2015-2016 HyperBit developers

import asyncio, concurrent.futures
import logging

from hyperbit import packet, pow, signal

logger = logging.getLogger(__name__)


class Worker(object):
    def __init__(self, db):
        """Worker that can compute object POWs."""
        logger.info('start')
        self._db = db
        self._db.execute('create table if not exists worker (obj, trials, extra, timestamp)')
        self._executor = concurrent.futures.ProcessPoolExecutor()
        for obj, trials, extra, timestamp in self._db.execute('select * from worker'):
            asyncio.get_event_loop().create_task(self._run(packet.Object.from_bytes(obj), trials, extra, timestamp))
        self.on_object_done = signal.Signal()
        """Called with an object when its POW has been computed."""

    @asyncio.coroutine
    def _run(self, obj, trials, extra, timestamp):
        ttl = int(obj.expires - timestamp)
        data = obj.data[8:]
        length = len(data) + 8 + extra
        loop = asyncio.get_event_loop()
        self._db.execute('insert into worker values (?, ?, ?, ?)',
                         (obj.data, trials, extra, timestamp))
        nonce = yield from loop.run_in_executor(self._executor, pow.pow, data, trials, extra, ttl)
        self._db.execute('delete from worker where obj = ?', (obj.data,))
        obj.nonce = nonce
        logger.info('object nonce computed')
        self.on_object_done.emit(obj)

    def add_object(self, obj, trials, extra, timestamp):
        """Queue an object for POW computation."""
        logger.info('compute nonce for object of length %s', len(obj.data))
        asyncio.get_event_loop().create_task(self._run(obj, trials, extra, timestamp))

