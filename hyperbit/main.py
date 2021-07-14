# Copyright 2015-2021 HyperBit developers

import asyncio
import logging
import sys

import _cffi_backend  # noqa:F401 for PyInstaller
try:
    import qasync
    from PyQt5 import QtWidgets
except ImportError:
    gui = None
else:
    from hyperbit.gui import gui

from hyperbit import core2


def main():
    if gui:
        app = QtWidgets.QApplication(sys.argv)
        asyncio.set_event_loop(qasync.QEventLoop(app))

    logging.basicConfig(
        level=logging.WARNING if gui else logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s')

    @asyncio.coroutine
    def run():
        core = core2.Core()
        if gui:
            window = gui.MainWindow(core)
            if not core.get_config('network.proxy'):
                if not window.configure_network():
                    return
            window.show()
        asyncio.get_event_loop().create_task(core.run())

    asyncio.get_event_loop().create_task(run())
    asyncio.get_event_loop().run_forever()
