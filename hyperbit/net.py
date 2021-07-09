# Copyright 2015-2016 HyperBit developers

import asyncio
import ipaddress
import socket


def ipv6(address):
    host = ipaddress.ip_address(address)
    if host.version == 4:
        host = ipaddress.IPv6Address(10 * b'\x00' + 2 * b'\xff' + host.packed)
    return host


class Connection(object):
    def __init__(self, host, port, socket=None):
        self.remote_host = host
        self.remote_port = port
        self._s = socket

    @asyncio.coroutine
    def connect(self):
        self._s = socket.socket()
        if self.remote_host.ipv4_mapped:
            host = ipaddress.IPv4Address(
                self.remote_host.packed[-4:]).compressed
        else:
            host = self.remote_host.compressed

        def func():
            try:
                self._s.connect((host, self.remote_port))
            except (OSError, ConnectionRefusedError):
                return False
            else:
                return True

        loop = asyncio.get_event_loop()
        return (yield from loop.run_in_executor(None, func))

    def send(self, data):
        try:
            self._s.send(data)
        except (OSError, BrokenPipeError):
            pass

    @asyncio.coroutine
    def recv(self, buffersize):
        def func():
            return self._s.recv(buffersize)
        loop = asyncio.get_event_loop()
        return (yield from loop.run_in_executor(None, func))

    def close(self):
        self._s.close()


class Listener(object):
    def __init__(self, port):
        self._s = socket.socket()
        self._s.bind(('0.0.0.0', port))
        self._s.listen(10)

    @asyncio.coroutine
    def accept(self):
        def func():
            return self._s.accept()
        loop = asyncio.get_event_loop()
        socket, address = yield from loop.run_in_executor(None, func)
        return Connection(ipv6(address[0]), address[1], socket)

    def close(self):
        self._s.close()
