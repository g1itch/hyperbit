# Copyright 2015 HyperBit developers

import sqlite3
import appdirs
import os

user_config_dir = appdirs.user_config_dir('hyperbit', '')
os.makedirs(user_config_dir, 0o700, exist_ok=True)
db2 = sqlite3.connect(os.path.join(user_config_dir, 'hyperbit.sqlite3'))
db2.execute('pragma synchronous = off')
db2.execute('pragma locking_mode = exclusive')
