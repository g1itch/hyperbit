
import unittest
from binascii import unhexlify

import ipaddress

from hyperbit import net, packet


# 500 identical peers:
# import ipaddress
# from hyperbit import net, packet
# [packet.Address(
#     1626611891, 1, 1, net.ipv6(ipaddress.ip_address('127.0.0.1')).packed,
#     8444
# ) for _ in range(1000)]
sample_data = unhexlify(
    'fd01f4' + (
        '0000000060f420b30000000'
        '1000000000000000100000000000000000000ffff7f00000120fc'
        ) * 500
)

# three addresses with the previous defaults, but with the timestamps:
# 281474976710890, 4503621617603182592, 10595693759686670352
sample_garbage = unhexlify(
    '030001'
    '0000000000ea0000000'
    '1000000000000000100000000000000000000ffff7f00000120fc'
    '3e801400000200000000000'
    '1000000000000000100000000000000000000ffff7f00000120fc'
    '930b775606f278100000000'
    '1000000000000000100000000000000000000ffff7f00000120fc'
)


class TestPacket(unittest.TestCase):
    """Test serializing and deserializing of packets"""

    def test_addr(self):
        addr_packet = packet.Addr.from_bytes(sample_data)
        self.assertEqual(len(addr_packet.addresses), 500)
        address = addr_packet.addresses[0]
        self.assertEqual(address.stream, 1)
        self.assertEqual(address.services, 1)
        self.assertEqual(address.time, 1626611891)
        self.assertEqual(
            address.ip, net.ipv6(ipaddress.ip_address('127.0.0.1')).packed)

        addr_packet = packet.Addr.from_bytes(sample_garbage)
        self.assertEqual(len(addr_packet.addresses), 0)
