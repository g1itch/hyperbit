# Copyright 2015-2016 HyperBit developers

import appdirs
import asyncio
import binascii
import logging
import os
import sqlite3
import time

from hyperbit import config, crypto, inventory, message, network, objscanner, objtypes, wallet, worker, packet

logger = logging.getLogger(__name__)


class Core(object):
    def __init__(self):
        logger.info('start')
        user_config_dir = appdirs.user_config_dir('hyperbit', '')
        self._dir = user_config_dir
        os.makedirs(user_config_dir, 0o700, exist_ok=True)
        self._db = sqlite3.connect(os.path.join(user_config_dir, 'hyperbit.sqlite3'))
        self._db.execute('pragma synchronous = off')
        self._db.execute('pragma locking_mode = exclusive')
        self._db.execute('create table if not exists config (id unique, value)')
        self.inv = inventory.Inventory(self._db)
        self.inv.load(self._dir)
        self.peers = network.PeerManager(self, self._db, self.inv)
        self.inv.on_add_object.connect(self.peers.send_inv)
        self.wal = wallet.Wallet(self._db)
        self.list = message.ThreadList(self._db)
        self.scanner = objscanner.Scanner(self._db, self.inv, self.wal)
        self.worker = worker.Worker(self._db)
        self.worker.on_object_done.connect(self.inv.add_object)
        self.wal.on_add_identity.connect(self.scan_identity)
        self.inv.on_add_object.connect(self.scan_object)
        self.scanner.on_scan_item.connect(self.do_scan)

    def save(self):
        logger.info('save')
        self.inv.save(self._dir)

    @asyncio.coroutine
    def _save(self):
        while True:
            self._db.commit()
            yield from asyncio.sleep(1)

    def get_config(self, key, default=None):
        return self._db.execute('select coalesce(min(value), ?) from config where id = ?', (default, key)).fetchone()[0]

    def set_config(self, key, value):
        self._db.execute('insert or replace into config (id, value) values (?, ?)', (key, value))

    @asyncio.coroutine
    def run(self):
        asyncio.get_event_loop().create_task(self._save())
        yield from self.peers.run()

    def scan_object(self, object):
        logger.info('scan object with hash %s', binascii.hexlify(object.hash).decode())
        self.scanner.scan(object.hash, None)
        for identity in self.wal.identities:
            self.scanner.scan(object.hash, identity)

    def scan_identity(self, identity):
        logger.info('scan identity with address %s', identity.address.to_str())
        for hash in self.inv.get_hashes():
            self.scanner.scan(hash, identity)

    def do_scan_msg_1(self, object, identity):
        try:
            decrypted = identity.decrypt(object.payload)
            msg = objtypes.MsgData.from_bytes(decrypted)
        except:
            pass
        else:
            if msg.encoding in [objtypes.Encoding.trivial, objtypes.Encoding.simple]:
                simple = objtypes.SimpleMessage.from_bytes(msg.message)
                channel = wallet.Address(4, config.NETWORK_STREAM, msg.ripe).to_bytes()
                creator = wallet.Address(4, config.NETWORK_STREAM, crypto.to_ripe(msg.verkey, msg.enckey)).to_bytes()
                reply = simple.subject[0:4] == 'Re: '
                if reply:
                    simple.subject = simple.subject[4:]

                for t in self.list.threads:
                    if t.channel == channel and t.subject == simple.subject:
                        thread = t
                        if not reply:
                            thread.creator = creator
                        break
                else:
                    if not reply:
                        thread = self.list.new_thread(channel, creator, simple.subject)
                    else:
                        thread = self.list.new_thread(channel, b'', simple.subject)
                if len(thread.longest) < len(simple.body):
                    thread.longest = simple.body
                if not reply:
                    for c in thread.comments:
                        if c.parent_text == '' and c.text == simple.body:
                            comment = c
                            comment.creator = creator
                            break
                    else:
                        comment = thread.new_comment('', creator, simple.body)
                else:
                    bodies = reversed(simple.body.split('\n'+54*'-'+'\n'))
                    parent_text = ''
                    for i, body in enumerate(bodies):
                        for c in thread.comments:
                            if c.text == body:
                                comment = c
                                comment.parent_text = parent_text
                                break
                        else:
                            comment = thread.new_comment(parent_text, b'', body)
                        parent_text = body
                    comment.creator = creator

    def do_scan(self, object, identity):
        if identity is None:
            return
        if object is None:
            return
        if object.type == objtypes.Type.msg and object.version == 1:
            self.do_scan_msg_1(object, identity)

    def send_message(self, src, dst, message):
        object = packet.Object(
            nonce=0,
            expires=int(time.time() + 4*24*60*60 + crypto.randint(-60*60, 60*60)),
            type=objtypes.Type.msg,
            version=1,
            stream=config.NETWORK_STREAM,
            payload=b'',
        )
        msg = objtypes.MsgData(
            addrver=4, stream=config.NETWORK_STREAM, behavior=0,
            verkey=src.profile.verkey, enckey=src.profile.enckey,
            trials=config.NETWORK_TRIALS, extra=config.NETWORK_EXTRA,
            ripe=dst.address.ripe,
            encoding=message.encoding, message=message.to_bytes(),
            ack=b'', signature=b''
        )
        msg.sign(src.sigkey, object)
        object.payload = crypto.encrypt(dst.enckey, msg.to_bytes())

        self.worker.add_object(object, config.NETWORK_TRIALS, config.NETWORK_EXTRA, int(time.time()))

