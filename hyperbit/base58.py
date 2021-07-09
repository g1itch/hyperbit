# Copyright 2015-2016 HyperBit developers

from hyperbit import crypto


def encode_raw(data):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    result = ''
    number = int.from_bytes(data, byteorder='big', signed=False)
    while number != 0:
        result = alphabet[number % len(alphabet)] + result
        number //= len(alphabet)
    result = (len(data) - len(data.lstrip(b'\x00'))) * alphabet[0] + result
    return result


def decode_raw(chars):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number = 0
    for char in chars:
        number = len(alphabet) * number + alphabet.index(char)
    data = number.to_bytes(
        (number.bit_length() + 7) // 8, byteorder='big', signed=False)
    data = (len(chars) - len(chars.lstrip(alphabet[0]))) * b'\x00' + data
    return data


def encode(data, prepend_bm=False):
    data += crypto.sha512d(data)[:4]
    text = encode_raw(data)
    if prepend_bm:
        text = 'BM-' + text
    return text


def decode(chars):
    chars = chars.strip()
    if chars[:3] == 'BM-':
        chars = chars[3:]
    data = decode_raw(chars)
    checksum = crypto.sha512d(data[:-4])[:4]
    assert checksum == data[-4:]
    return data[:-4]


def encode_wif(data):
    data = b'\x80' + data
    data = data + crypto.sha256d(data)[:4]
    return encode_raw(data)


def decode_wif(chars):
    chars = chars.strip()
    data = decode_raw(chars)
    checksum = crypto.sha256d(data[:-4])[:4]
    assert checksum == data[-4:]
    assert data[0:1] == b'\x80'
    return data[1:-4]
