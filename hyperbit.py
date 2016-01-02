# Copyright 2015 HyperBit developers

import asyncio
import quamash
import sys
from PyQt5.QtWidgets import QApplication, QDialog
import _cffi_backend # for Pyinstaller
import socks
import socket

from hyperbit import core2, database
from hyperbit.gui import gui


app = QApplication(sys.argv)
asyncio.set_event_loop(quamash.QEventLoop(app))

@asyncio.coroutine
def save():
    while True:
        database.db2.commit()
        yield from asyncio.sleep(1)

@asyncio.coroutine
def run():
    core = core2.Core()
    window = gui.MainWindow(core)
    if not core.get_config('network.proxy'):
        if not window.configure_network():
            return
    asyncio.get_event_loop().create_task(core.run())
    window.show()

asyncio.get_event_loop().create_task(run())
asyncio.get_event_loop().create_task(save())
asyncio.get_event_loop().run_forever()



