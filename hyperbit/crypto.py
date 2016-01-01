# Copyright 2015 HyperBit developers

from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes, padding
from hyperbit import serialize
import hashlib
import os


def _point_multiply(priv, curve=ec.SECP256K1()):
    b = openssl.backend
    with b._tmp_bn_ctx() as ctx:
        curve_nid = b._elliptic_curve_to_nid(curve)
        ec_cdata = b._lib.EC_KEY_new_by_curve_name(curve_nid)
        ec_cdata = b._ffi.gc(ec_cdata, b._lib.EC_KEY_free)
        bn = b._int_to_bn(priv)
        b._lib.EC_KEY_set_private_key(ec_cdata, bn)
        pkey = b._lib.EC_KEY_new_by_curve_name(curve_nid)
        group = b._lib.EC_KEY_get0_group(pkey)
        pkey = b._lib.EC_POINT_new(group)
        pkey = b._ffi.gc(pkey, b._lib.EC_POINT_free)
        b._lib.EC_POINT_mul(group, pkey, bn, b._ffi.NULL, b._ffi.NULL, ctx)
        x = b._int_to_bn(0)
        y = b._int_to_bn(0)
        b._lib.EC_POINT_get_affine_coordinates_GFp(group, pkey, x, y, ctx)
        return b._bn_to_int(x), b._bn_to_int(y)


def _priv_to_private(privkey):
    assert len(privkey) == 32
    private_value = int.from_bytes(privkey, 'big')
    x, y = _point_multiply(private_value)
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1())
    private_numbers = ec.EllipticCurvePrivateNumbers(private_value, public_numbers)
    return private_numbers.private_key(openssl.backend)


def _pub_to_public(pubkey):
    assert len(pubkey) == 65
    assert pubkey[0:1] == b'\x04'
    x = int.from_bytes(pubkey[1:33], 'big')
    y = int.from_bytes(pubkey[33:65], 'big')
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1())
    return public_numbers.public_key(openssl.backend)


def gen_priv():
    k = ec.generate_private_key(ec.SECP256K1(), openssl.backend)
    return k.private_numbers().private_value.to_bytes(32, 'big')


def priv_to_pub(privkey):
    assert len(privkey) == 32
    x, y = _point_multiply(int.from_bytes(privkey, 'big'))
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def encrypt(pubkey, data):
    public_key = _pub_to_public(pubkey)
    private_key = ec.generate_private_key(ec.SECP256K1(), openssl.backend)
    secret = private_key.exchange(ec.ECDH(), public_key)
    key = hashlib.sha512(secret).digest()
    enckey = key[0:32]
    mackey = key[32:64]
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    paddeddata = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(enckey), modes.CBC(iv), openssl.backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(paddeddata) + encryptor.finalize()
    s = serialize.Serializer()
    s.bytes(iv)
    s.uint(0x02ca, 2)
    public_numbers = private_key.public_key().public_numbers()
    x = public_numbers.x.to_bytes(32, 'big').lstrip(b'\x00')
    s.uint(len(x), 2)
    s.bytes(x)
    y = public_numbers.y.to_bytes(32, 'big').lstrip(b'\x00')
    s.uint(len(y), 2)
    s.bytes(y)
    s.bytes(ciphertext)
    maccer = HMAC(mackey, hashes.SHA256(), openssl.backend)
    maccer.update(s.data)
    mac = maccer.finalize()
    s.bytes(mac)
    return s.data


def decrypt(privkey, data):
    s = serialize.Deserializer(data)
    iv = s.bytes(16)
    curve = s.uint(2)
    assert curve == 0x02ca
    x_len = s.uint(2)
    assert x_len <= 32 # TODO Should we assert this? And should we assert no leading zero bytes?
    x = s.bytes(x_len)
    y_len = s.uint(2)
    assert y_len <= 32 # TODO Should we assert this? And should we assert no leading zero bytes?
    y = s.bytes(y_len)
    encrypted = s.bytes(-32)
    assert encrypted != b''
    mac = s.bytes(32)
    pubkey = b'\x04' + x.rjust(32, b'\x00') + y.rjust(32, b'\x00')
    public_key = _pub_to_public(pubkey)
    private_key = _priv_to_private(privkey)
    secret = private_key.exchange(ec.ECDH(), public_key)
    key = hashlib.sha512(secret).digest()
    enckey = key[0:32]
    mackey = key[32:64]
    maccer = HMAC(mackey, hashes.SHA256(), openssl.backend)
    maccer.update(data[0:-32])
    maccer.verify(mac)
    cipher = Cipher(algorithms.AES(enckey), modes.CBC(iv), openssl.backend)
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def verify(pubkey, data, signature):
    public_key = _pub_to_public(pubkey)
    verifier = public_key.verifier(signature, ec.ECDSA(hashes.SHA256()))
    verifier.update(data)
    verifier.verify()


def sign(privkey, data):
    private_key = _priv_to_private(privkey)
    signer = private_key.signer(ec.ECDSA(hashes.SHA256()))
    signer.update(data)
    return signer.finalize()


def bm160(data):
    sha = hashlib.sha512(data).digest()
    return hashlib.new('ripemd160', sha).digest()

def sha256d(data):
    sha = hashlib.sha256(data).digest()
    return hashlib.sha256(sha).digest()

def sha512(data):
    return hashlib.sha512(data).digest()

def sha512d(data):
    sha = hashlib.sha512(data).digest()
    return hashlib.sha512(sha).digest()

def urandom(size):
    return os.urandom(size)

def randint(min, max):
    assert min <= max
    count = 1 + max - min
    assert count <= 2**64
    random = int.from_bytes(os.urandom(128//8), 'big')
    return min + random%count

