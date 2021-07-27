
import unittest
from binascii import unhexlify

from hyperbit import serialize


class TestSerialize(unittest.TestCase):
    """Test serializing and deserializing data"""

    def test_varint(self):
        """Test varint serializing and deserializing"""
        s = serialize.Serializer()
        s.vint(0)
        self.assertEqual(s.data, b'\x00')
        s = serialize.Serializer()
        s.vint(42)
        self.assertEqual(s.data, b'*')
        s = serialize.Serializer()
        s.vint(252)
        self.assertEqual(s.data, unhexlify('fc'))
        s = serialize.Serializer()
        s.vint(253)
        self.assertEqual(s.data, unhexlify('fd00fd'))
        s = serialize.Serializer()
        s.vint(100500)
        self.assertEqual(s.data, unhexlify('fe00018894'))
        s = serialize.Serializer()
        s.vint(65535)
        self.assertEqual(s.data, unhexlify('fdffff'))
        s = serialize.Serializer()
        s.vint(4294967295)
        self.assertEqual(s.data, unhexlify('feffffffff'))
        s = serialize.Serializer()
        s.vint(4294967296)
        self.assertEqual(s.data, unhexlify('ff0000000100000000'))
        s = serialize.Serializer()
        s.vint(18446744073709551615)
        self.assertEqual(s.data, unhexlify('ffffffffffffffffff'))

        d = serialize.Deserializer(b'\xfeaddr')
        self.assertEqual(d.vint(), 0x61646472)
        d = serialize.Deserializer(b'\xfe\x00tor')
        self.assertEqual(d.vint(), 0x746f72)
