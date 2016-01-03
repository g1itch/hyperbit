# Copyright 2015-2016 HyperBit developers

from hyperbit import crypto
from hyperbit.gui import qidenticon


def get(data, size=10):
    # TODO salt identicons
    if data == b'':
        hash = b''
    else:
        hash = crypto.sha512(data)
    return qidenticon.render_identicon(int.from_bytes(hash, 'big'), size, True, 0, 0)
