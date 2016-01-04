# Copyright 2015-2016 HyperBit developers

import functools
import weakref


class Signal(object):
    def __init__(self):
        self._slots = dict()
        self._names = dict()

    def _del_slot(self, ref):
        del self._slots[ref]

    def _del_name(self, name):
        del self._names[name]

    def _ref(self, func):
        try:
            return weakref.WeakMethod(func, callback=self._del_slot)
        except TypeError:
            try:
                return weakref.ref(func, callback=self._del_slot)
            except TypeError:
                return func

    def connect(self, func, *args):
        if hasattr(func, '__call__'):
            ref = self._ref(func)
            assert ref not in self._slots
            self._slots[ref] = (ref, args)
        else:
            if func not in self._names:
                self._names[func] = Signal()
                self._names[func]._on_empty = functools.partial(self._del_name, func)
            self._names[func].connect(*args)

    def disconnect(self, func, *args):
        if hasattr(func, '__call__'):
            assert len(args) == 0
            del self._slots[self._ref(func)]
            if hasattr(self, '_on_empty') and not self._slots:
                self._on_empty()
        else:
            self._names[func].disconnect(*args)

    def emit(self, *args):
        for ref, bound in self._slots.copy().values():
            if isinstance(ref, weakref.ref):
                func = ref()
                if func:
                    func(*(bound+args))
                else:
                    del self._slots[ref]
            else:
                ref(*(bound+args))
        try:
            name = self._names[args[0]]
        except (IndexError, KeyError, TypeError):
            pass
        else:
            name.emit(*(args[1:]))

