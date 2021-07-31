# Copyright 2015-2016 HyperBit developers

from hyperbit import crypto
from hyperbit.gui import qidenticon


def get(data, size=10, gray=False, token=None):
    salt = crypto._bm160(token.encode())[:8] if token else b''
    if data == b'':
        hash = b''
    else:
        hash = crypto.sha512(data + salt)
    return qidenticon.render_identicon(
        int.from_bytes(hash, 'big'), size, True, gray)
