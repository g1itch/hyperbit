# Copyright 2015-2016 HyperBit developers

import logging
import sys

from hyperbit.main import main

logging.basicConfig(level=logging.INFO)


if __name__ == '__main__':
    sys.exit(main())

