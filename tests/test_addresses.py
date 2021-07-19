
import unittest
from binascii import unhexlify

from hyperbit import base58, crypto, wallet


# stream: 1, version: 2
sample_ripe = unhexlify('003cd097eb7f35c87b5dc8b4538c22cb55312a9f')
sample_address = 'BM-onkVu1KKL2UaUss5Upg9vXmqd3esTmV79'


class TestAddresses(unittest.TestCase):
    """Test addresses manipulations"""

    def test_decode(self):
        """Create Address from str and check its parameters"""
        addr = wallet.Address.from_str(sample_address)
        self.assertEqual(addr.stream, 1)
        self.assertEqual(addr.version, 2)
        self.assertEqual(addr.ripe, sample_ripe)
        addr1 = wallet.Address.from_str('2cWzSnwjJ7yRP3nLEWUV5LisTZyREWSzUK')
        self.assertEqual(addr1.stream, 1)
        self.assertEqual(addr1.version, 4)
        addr2 = wallet.Address.from_str('2DBPTgeSawWYZceFD69AbDT5q4iUWtj1ZN')
        self.assertEqual(addr2.stream, 1)
        self.assertEqual(addr2.version, 3)
        self.assertEqual(addr1.ripe, addr2.ripe)

    def test_base58(self):
        """Check Base58 encoding and decoding"""
        self.assertEqual(
            int.from_bytes(
                base58.decode_raw('2cWzSnwjJ7yRP3nLEWUV5LisTZyREWSzUK'),
                byteorder='big'),
            25152821841976547050350277460563089811513157529113201589004)
        self.assertEqual(
            int.from_bytes(
                base58.decode_raw('2DBPTgeSawWYZceFD69AbDT5q4iUWtj1ZN'),
                byteorder='big'),
            18875720106589866286514488037355423395410802084648916523381)
        # self.assertEqual(
        #     int.from_bytes(
        #         base58.decode('BM-2cWzSnwjJ7yRP3nLEWUV5LisTZyREWSzUK'),
        #         byteorder='big'),
        #     25152821841976547050350277460563089811513157529113201589004)
        # self.assertEqual(
        #     '2cWzSnwjJ7yRP3nLEWUV5LisTZyREWSzUK',
        #     base58.encode_raw(
        #         25152821841976547050350277460563089811513157529113201589004))
        # self.assertEqual(
        #     '2DBPTgeSawWYZceFD69AbDT5q4iUWtj1ZN',
        #     base58.encode_raw(
        #         18875720106589866286514488037355423395410802084648916523381))

    def test_encode(self):
        """Create addresse, convert it to str and check the result"""
        addr = wallet.Address(2, 1, sample_ripe)
        self.assertEqual(addr.to_str(), sample_address[3:])

    def test_wif(self):
        """Decode well known WIFs and compare the result to known address"""
        addr = wallet.Address(
            4, 1, crypto.to_ripe(
                crypto.priv_to_pub(base58.decode_wif(
                    '5K42shDERM5g7Kbi3JT5vsAWpXMqRhWZpX835M2pdSoqQQpJMYm')),
                crypto.priv_to_pub(base58.decode_wif(
                    '5HwugVWm31gnxtoYcvcK7oywH2ezYTh6Y4tzRxsndAeMi6NHqpA'))))
        # [chan] bitmessage
        self.assertEqual(
            addr.to_str(), '2cWy7cvHoq3f1rYMerRJp8PT653jjSuEdY')
