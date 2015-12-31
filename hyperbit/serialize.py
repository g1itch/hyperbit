# Copyright 2015 HyperBit developers


class Serializer:
    def __init__(self):
        self.data = b''

    def uint(self, value, size):
        self.data += value.to_bytes(size, byteorder='big', signed=False)

    def int(self, value, size):
        self.data += value.to_bytes(size, byteorder='big', signed=True)

    def bytes(self, value):
        self.data += value

    def str(self, value):
        self.data += bytes(value, 'utf8')

    def vint(self, value):
        if value <= 0xfc:
            self.uint(value, 1)
        elif value <= 0xffff:
            self.uint(0xfd, 1)
            self.uint(value, 2)
        elif value <= 0xffffffff:
            self.uint(0xfe, 1)
            self.uint(value, 4)
        else:
            self.uint(0xff, 1)
            self.uint(value, 8)

    def vbytes(self, value):
        self.vint(len(value))
        self.bytes(value)

    def vstr(self, value):
        buffer = bytes(value, 'utf8')
        self.vint(len(buffer))
        self.bytes(buffer)


class Deserializer:
    def __init__(self, data):
        self._data = data
        self._index = 0

    def bytes(self, size=None):
        if size is None:
            buffer = self._data[self._index:]
            self._index = len(self._data)
        elif size >= 0:
            buffer = self._data[self._index:self._index+size]
            self._index += size
        else:
            buffer = self._data[self._index:size]
            self._index = len(self._data) + size
        return buffer

    def uint(self, size):
        return int.from_bytes(self.bytes(size), byteorder='big', signed=False)

    def int(self, size):
        return int.from_bytes(self.bytes(size), byteorder='big', signed=True)

    def str(self, size=None):
        return str(self.bytes(size), 'utf8')

    def vint(self):
        buffer = self.uint(1)
        if buffer <= 0xfc:
            return buffer
        elif buffer == 0xfd:
            return self.uint(2)
        elif buffer == 0xfe:
            return self.uint(4)
        else:
            return self.uint(8)

    def vbytes(self):
        size = self.vint()
        return self.bytes(size)

    def vstr(self):
        size = self.vint()
        return self.str(size)

    @property
    def data(self):
        return self._data[self._index:]
