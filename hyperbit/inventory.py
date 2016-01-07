# Copyright 2015-2016 HyperBit developers

import asyncio
import logging
import os
import time

from hyperbit import config, packet, signal

logger = logging.getLogger(__name__)


class Inventory(object):
    def __init__(self, db):
        logger.info('start')
        self._db = db
        self._objects = dict()
        self._total_size = 0
        self.on_add_object = signal.Signal()
        self.on_remove_object = signal.Signal()
        asyncio.get_event_loop().call_soon(self._cleanup)
        self.on_stats_changed = signal.Signal()

    def load(self, dir):
        logger.info('load')
        try:
            with open(os.path.join(dir, 'inventory.dat'), 'rb') as f:
                while True:
                    headerdata = f.read(24)
                    if not headerdata:
                        break
                    header = packet.Header.from_bytes(headerdata)
                    obj = packet.Object.from_bytes(f.read(header.length))
                    self.add_object(obj)
        except FileNotFoundError:
            logger.warning('inventory.dat not found')
        if self._db.execute('select count(*) from sqlite_master where name = "objects"').fetchone()[0]:
            for data, in self._db.execute('select data from objects'):
                obj = packet.Object.from_bytes(data)
                self._objects[obj.hash] = obj
            self._db.execute('drop table objects')
            self.save(dir)

    def save(self, dir):
        logger.info('save')
        with open(os.path.join(dir, 'inventory.dat'), 'wb') as f:
            for obj in self._objects.values():
                f.write(packet.Header(
                    magic=0,
                    command=obj.command,
                    length=len(obj.data),
                    checksum=bytes(4)
                ).to_bytes())
                f.write(obj.data)

    def _cleanup(self):
        logger.info('cleanup')
        start = int(time.time())-3*60*60
        objs = [obj for obj in self._objects.values() if obj.expires < start < start]
        for obj in objs:
            self.on_remove_object.emit(obj)
            self._total_size -= len(obj.data)
            del self._objects[obj.hash]
        if objs:
            self.on_stats_changed.emit()
        asyncio.get_event_loop().call_later(config.CLEANUP_INTERVAL, self._cleanup)

    def get_object(self, hash):
        if hash in self._objects:
            return self._objects[hash]
        else:
            return None

    def add_object(self, obj):
        if obj.hash in self._objects:
            return
        now = int(time.time())
        start = now
        end = now+28*24*60*60
        margin = 3*60*60
        if not obj.check_pow(config.NETWORK_TRIALS, config.NETWORK_EXTRA, start+margin):
            return
        if not start-margin <= obj.expires <= end+margin:
            return
        self._objects[obj.hash] = obj
        self._total_size += len(obj.data)
        self.on_add_object.emit(obj)
        self.on_stats_changed.emit()

    def count(self):
        return len(self._objects)

    def get_hashes(self):
        return self._objects.keys()

    #FIXME When objects are added before they are officially
    #FIXME valid they should not be sent until they are.
    #FIXME This is quite complicated to implement though
    #FIXME and not implementing it should not have any
    #FIXME major effects.
    def get_hashes_for_send(self):
        now = int(time.time())
        start = now-28*24*60*60
        end = now
        return [obj.hash for obj in self._objects.values() if start <= obj.expires <= end]

    def get_total_size(self):
        return self._total_size
