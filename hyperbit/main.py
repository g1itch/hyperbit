# Copyright 2015 HyperBit developers

import asyncio
import binascii
import ipaddress
import pickle
import random
from binascii import hexlify

from hyperbit import config, inventory, network, objtypes, packet, wallet, base58, crypto


def create_object(om, loop):
    obj = packet.Object()
    addr = wallet.Address.from_str('BM-2cX2FdSgU2S7MHUNHdh7smTLqhuc5cKTvm')
    #ripe = base58.decode(addr.to_str())
    ripe = addr.to_bytes()
    tag = crypto.sha512d(ripe)[32:]
    print(hexlify(tag))
    obj.type = objtypes.Type.getpubkey
    obj.version = 4
    obj.payload = tag
    print('begin')
    yield from obj.complete(loop=loop)
    print(hexlify(obj.hash))
    print('done')
    om.add_object(obj)



if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    inv = inventory.Inventory(loop=loop)
    network.PeerManager(om=inv, loop=loop)
    loop.create_task(create_object(om=inv, loop=loop))
    loop.run_forever()


