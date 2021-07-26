# Copyright 2015-2016 HyperBit developers

import asyncio
import binascii
import logging
import os
import sqlite3
import time

import appdirs

from hyperbit import (
    config, crypto, inventory, message, network,
    objscanner, objtypes, wallet, worker, packet
)

logger = logging.getLogger(__name__)


class Core():
    def __init__(self):
        logger.debug('start')
        user_config_dir = appdirs.user_config_dir('hyperbit', '')
        os.makedirs(user_config_dir, 0o700, exist_ok=True)
        self._db = sqlite3.connect(
            os.path.join(user_config_dir, 'hyperbit.sqlite3'))
        self._db.execute('PRAGMA synchronous = off')
        self._db.execute('PRAGMA locking_mode = exclusive')

        self._db.execute(
            'CREATE TABLE IF NOT EXISTS config (id unique, value)')
        self.inv = inventory.Inventory(self._db)
        self.peers = network.PeerManager(self, self._db, self.inv)
        self.inv.on_add_object.append(self.peers.send_inv)
        self.wal = wallet.Wallet(self._db)
        self.list = message.ThreadList(self._db)
        self.scanner = objscanner.Scanner(self._db, self.inv, self.wal)
        self.worker = worker.Worker(self._db)
        self.worker.on_object_done.append(self.inv.add_object)
        self.wal.on_add_identity.append(self.scan_identity)
        self.inv.on_add_object.append(self.scan_object)
        self.scanner.on_scan_item.append(self.do_scan)

    @asyncio.coroutine
    def _save(self):
        while True:
            self._db.commit()
            yield from asyncio.sleep(1)

    def get_config(self, key, default=None):
        return self._db.execute(
            'SELECT coalesce(min(value), ?) FROM config WHERE id = ?',
            (default, key)
        ).fetchone()[0]

    def set_config(self, key, value):
        self._db.execute(
            'INSERT OR REPLACE INTO config (id, value) VALUES (?, ?)',
            (key, value)
        )

    @asyncio.coroutine
    def run(self):
        asyncio.get_event_loop().create_task(self._save())
        yield from self.peers.run()

    def scan_object(self, obj):
        if obj.type == objtypes.Type.onionpeer:
            peer = objtypes.Onionpeer.from_bytes(obj.payload)
            self.peers.new_peer(
                obj.expires - 7 * 24 * 3600, 1, peer.host, peer.port)
            return
        logger.debug(
            'scan object with hash %s', binascii.hexlify(obj.hash).decode())
        self.scanner.scan(obj.hash, None)
        for identity in self.wal.identities:
            self.scanner.scan(obj.hash, identity)

    def scan_identity(self, identity):
        logger.info('scan identity with address %s', identity.address.to_str())
        for invhash in self.inv.get_hashes():
            self.scanner.scan(invhash, identity)

    def do_scan_msg_1(self, obj, identity):
        try:
            decrypted = identity.decrypt(obj.payload)
            msg = objtypes.MsgData.from_bytes(decrypted)
        except Exception:  # TODO: exception type
            pass
        else:
            if msg.encoding in [
                    objtypes.Encoding.trivial, objtypes.Encoding.simple]:
                simple = objtypes.SimpleMessage.from_bytes(msg.message)
                channel = wallet.Address(
                    4, config.NETWORK_STREAM, msg.ripe).to_bytes()
                creator = wallet.Address(
                    4, config.NETWORK_STREAM,
                    crypto.to_ripe(msg.verkey, msg.enckey)).to_bytes()
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
                        thread = self.list.new_thread(
                            channel, creator, simple.subject)
                    else:
                        thread = self.list.new_thread(
                            channel, b'', simple.subject)
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
                    for body in bodies:
                        for c in thread.comments:
                            if c.text == body:
                                comment = c
                                comment.parent_text = parent_text
                                break
                        else:
                            comment = thread.new_comment(
                                parent_text, b'', body)
                        parent_text = body
                    comment.creator = creator

    def do_scan(self, obj, identity):
        if identity is None:
            return
        if obj is None:
            return
        if obj.type == objtypes.Type.msg and obj.version == 1:
            self.do_scan_msg_1(obj, identity)

    def send_message(self, src, dst, msg):
        obj = packet.Object(
            nonce=0,
            expires=int(
                time.time() + 4 * 24 * 60 * 60
                + crypto.randint(-60 * 60, 60 * 60)
            ),
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
            encoding=msg.encoding, message=msg.to_bytes(),
            ack=b'', signature=b''
        )
        msg.sign(src.sigkey, obj)
        obj.payload = crypto.encrypt(dst.enckey, msg.to_bytes())

        self.worker.add_object(
            obj, config.NETWORK_TRIALS, config.NETWORK_EXTRA, int(time.time()))
