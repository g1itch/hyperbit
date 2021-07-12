
import unittest
from binascii import unhexlify

from hyperbit import crypto


sample_pubsigningkey = unhexlify(
    '4a367f049ec16cb6b6118eb734a9962d10b8db59c890cd08f210c43ff08bdf09d'
    '16f502ca26cd0713f38988a1237f1fc8fa07b15653c996dc4013af6d15505ce')
sample_pubencryptionkey = unhexlify(
    '4597d59177fc1d89555d38915f581b5ff2286b39d022ca0283d2bdd5c36be5d3c'
    'e7b9b97792327851a562752e4b79475d1f51f5a71352482b241227f45ed36a9')
sample_privsigningkey = unhexlify(
    '93d0b61371a54b53df143b954035d612f8efa8a3ed1cf842c2186bfd8f876665')
sample_privencryptionkey = unhexlify(
    '4b0b73a54e19b059dc274ab69df095fe699f43b17397bca26fdf40f4d7400a3a')
sample_ripe = unhexlify('003cd097eb7f35c87b5dc8b4538c22cb55312a9f')
# stream: 1, version: 2
# sample_address = 'BM-onkVu1KKL2UaUss5Upg9vXmqd3esTmV79'

sample_factor = 66858749573256452658262553961707680376751171096153613379801854825275240965733
# G * sample_factor
sample_point = (
    33567437183004486938355437500683826356288335339807546987348409590129959362313,
    94730058721143827257669456336351159718085716196507891067256111928318063085006
)


class TestCrypto(unittest.TestCase):
    """Test crypto functions"""

    def test__point_multiply(self):
        self.assertEqual(
            sample_point,
            crypto._point_multiply(sample_factor))

    def test_priv_to_pub(self):
        """Generate public keys and check the result"""
        self.assertEqual(
            crypto.priv_to_pub(sample_privsigningkey),
            sample_pubsigningkey)
        self.assertEqual(
            crypto.priv_to_pub(sample_privencryptionkey),
            sample_pubencryptionkey)

    def test_to_ripe(self):
        """Check the ripe generated from pubkeys"""
        ripe_hash = crypto.to_ripe(
            sample_pubsigningkey, sample_pubencryptionkey)
        self.assertEqual(ripe_hash, sample_ripe)
