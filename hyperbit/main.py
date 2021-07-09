# Copyright 2015-2016 HyperBit developers

import asyncio
import _cffi_backend  # noqa:F401 for PyInstaller
import sys

import qasync
from PyQt5.QtWidgets import QApplication

from hyperbit import core2
from hyperbit.gui import gui


def main():
    app = QApplication(sys.argv)
    asyncio.set_event_loop(qasync.QEventLoop(app))

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
    asyncio.get_event_loop().run_forever()
