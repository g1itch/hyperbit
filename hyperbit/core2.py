# Copyright 2015 HyperBit developers

from hyperbit import config, crypto, inventory, message, network, objscanner, objtypes, wallet, database

class Core(object):
    def __init__(self):
        self._db = database.db2
        self.inv = inventory.Inventory(self._db)
        self.peers = network.PeerManager(self.inv)
        self.inv.on_add_object.append(self.peers.send_inv)
        self.wal = wallet.Wallet(self._db)
        self.list = message.ThreadList()
        self.scanner = objscanner.Scanner(self.inv, self.wal)
        self.wal.on_add_identity.append(self.scan_identity)
        self.inv.on_add_object.append(self.scan_object)
        self.scanner.on_scan_item.append(self.do_scan)

    def scan_object(self, object):
        self.scanner.scan(object.hash, None)
        for identity in self.wal.identities:
            self.scanner.scan(object.hash, identity)
            #check_object_identity(object, identity)

    def scan_identity(self, identity):
        for hash in self.inv.get_hashes():
            self.scanner.scan(hash, identity)
            #check_object_identity(object, identity)

    def do_scan(self, object, identity):
        if identity is None:
            return
        if object is None:
            return
        list = self.list
        if object.type == objtypes.Type.msg and object.version == 1:
            try:
                decrypted = identity.decrypt(object.payload)
                msg = objtypes.MsgData.from_bytes(decrypted)
            except:
                pass
            else:
                if msg.encoding in [1, 2]:
                    text = msg.message.decode(errors='replace')
                    if text[0:8] == 'Subject:':
                        index = text.find('\nBody:', 8)
                        if index == -1:
                            subject = text[8:]
                            body = ''
                        else:
                            subject = text[8:index]
                            body = text[index+6:]
                    else:
                        subject = ''
                        body = text
                    channel = wallet.Address(4, 1, msg.ripe).to_bytes()
                    creator = wallet.Address(4, 1, crypto.bm160(msg.verkey + msg.enckey)).to_bytes()
                    reply = subject[0:4] == 'Re: '
                    if reply:
                        subject = subject[4:]

                    for t in list.threads:
                        if t.channel == channel and t.subject == subject:
                            thread = t
                            if not reply:
                                thread.creator = creator
                            break
                    else:
                        if not reply:
                            thread = self.list.new_thread(channel, creator, subject)
                        else:
                            thread = self.list.new_thread(channel, b'', subject)
                    if len(thread.longest) < len(body):
                        thread.longest = body
                    if not reply:
                        for c in thread.comments:
                            if c.parent_text == '' and c.text == body:
                                comment = c
                                comment.creator = creator
                                break
                        else:
                            comment = thread.new_comment('', creator, body)
                    else:
                        bodies = reversed(body.split('\n'+54*'-'+'\n'))
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

                    """
                    for t in list.threads:
                        if t.subject == subject:
                            thread = t
                            break
                    else:
                        thread = message.Thread(identity, subject)
                        list.add_thread(thread)
                    if reply:
                        bodies = body.split('\n'+54*'-'+'\n')
                        for i, body in enumerate(reversed(bodies)):
                            for c in thread.bodies:
                                if c.text == body:
                                    comment = c
                                    break
                            else:
                                comment = message.Comment(body, True)
                                thread.insert_comment(len(thread.bodies), comment)
                            if i + 1 == len(bodies):
                                comment.set_ghost(False)
                    else:
                        if len(thread.bodies) > 0 and thread.bodies[0].text == body:
                            thread.bodies[0].set_ghost(False)
                        else:
                            comment = message.Comment(body, False)
                            thread.insert_comment(0, comment)
                    """
