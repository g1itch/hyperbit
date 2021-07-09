# Copyright 2015-2016 HyperBit developers

import asyncio
import concurrent.futures

from hyperbit import packet, pow


class Worker(object):
    def __init__(self, db):
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

    def add_object(self, obj, trials, extra, timestamp):
        asyncio.get_event_loop().create_task(self._run(
            obj, trials, extra, timestamp))
