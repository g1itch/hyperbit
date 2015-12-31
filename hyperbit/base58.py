# Copyright 2015 HyperBit developers

import hashlib

def encode(data, prepend_bm=False):
    data += hashlib.sha512(hashlib.sha512(data).digest()).digest()[:4]
    map = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    result = ''
    number = int.from_bytes(data, byteorder='big', signed=False)
    while number != 0:
        result = map[number%len(map)] + result
        number //= len(map)
    result = (len(data)-len(data.lstrip(b'\x00')))*map[0] + result
    if prepend_bm:
        result = 'BM-' + result
    return result


def decode(chars):
    map = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number = 0
    chars = chars.strip()
    if chars[:3] == 'BM-':
        chars = chars[3:]
    for char in chars:
        number = len(map) * number + map.index(char)
    data = number.to_bytes((number.bit_length()+7)//8, byteorder='big', signed=False)
    data = (len(chars)-len(chars.lstrip(map[0])))*b'\x00' + data
    checksum = hashlib.sha512(hashlib.sha512(data[:-4]).digest()).digest()[:4]
    assert checksum == data[-4:]
    return data[:-4]
