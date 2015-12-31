# Copyright 2015 HyperBit developers

from hyperbit import packet, objtypes, config, crypto, inventory
import time


def create_message(subject, body, parent=None):
    if parent is None:
        return ('Subject:'+subject+'\nBody:'+body).encode()
    else:
        return ('Subject:Re: '+subject+'\nBody:'+body+'\n'+54*'-'+'\n'+parent).encode()


def send_message(src, dst, encoding, message, inv):
    object = packet.Object()
    object.nonce = 0
    object.expires = int(time.time() + 4*24*60*60 + crypto.randint(-60*60, 60*60))
    object.type = objtypes.Type.msg
    object.version = 1
    object.stream = 1
    object.payload = b''
    msg = objtypes.MsgData(
            addrver=4, stream=1, behavior=0,
            verkey=src.profile.verkey, enckey=src.profile.enckey,
            trials=config.NETWORK_TRIALS, extra=config.NETWORK_EXTRA,
            ripe=dst.address.ripe,
            encoding=encoding, message=message,
            ack=b'', signature=b'')
    msg.sign(src.sigkey, object)
    object.payload = crypto.encrypt(dst.enckey, msg.to_bytes())
    inv.add_object_without_pow(object, config.NETWORK_TRIALS, config.NETWORK_EXTRA, int(time.time()))

