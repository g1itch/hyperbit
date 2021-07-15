# Copyright 2015-2016 HyperBit developers

import os

from hyperbit import crypto


def do_pow(payload, trials, extra, ttl):
    length = len(payload) + 8 + extra
    target = int(2**64 / (trials * (length + max(ttl, 0) * length / (2**16))))
    value = target + 1
    initial = crypto.sha512(payload)
    # Make it harder for attackers to determine how many numbers we have tried
    nonce = int.from_bytes(os.urandom(8), 'big')
    while value > target:
        nonce = (nonce + 1) % (2**64)
        a = nonce.to_bytes(8, 'big')
        c = crypto.sha512d(a + initial)
        value = int.from_bytes(c[:8], 'big')
    return nonce


def check(payload, trials, extra, ttl, nonce):
    length = len(payload) + 8 + extra
    target = int(2**64 / (trials * (length + ttl * length / (2**16))))
    initial = crypto.sha512(payload)
    a = nonce.to_bytes(8, 'big')
    c = crypto.sha512d(a + initial)
    value = int.from_bytes(c[:8], 'big')
    return value <= target
