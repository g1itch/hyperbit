# Copyright 2015-2021 HyperBit developers

import asyncio
import ipaddress
import socket


def ipv6(address):
    host = ipaddress.ip_address(address)
    if host.version == 4:
        host = ipaddress.IPv6Address(10 * b'\x00' + 2 * b'\xff' + host.packed)
    return host


class Connection():
    """An asyncronous tcp socket connection"""
    def __init__(self, host, port, socket=None):
        self.remote_host = host
        self.remote_port = port
        self._s = socket

    @asyncio.coroutine
    def connect(self):
        """Establish a connection. Return True on succes, else return False."""
        if self._s:
            return True

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
        """Send data. Return True on success, else return False."""
        try:
            self._s.sendall(data)
        except (OSError, BrokenPipeError):
            return False
        else:
            return True

    @asyncio.coroutine
    def recv(self, size):
        """Receive exactly size bytes. Return None in case of error."""
        def func():
            try:
                buf = b''
                while len(buf) < size:
                    buf += self._s.recv(size - len(buf))
                return buf
            except ConnectionResetError:
                return None
        loop = asyncio.get_event_loop()
        return (yield from loop.run_in_executor(None, func))

    def shutdown(self):
        """
        Close the connection and terminate a pending connect or recv call.
        """
        self._s.shutdown(socket.SHUT_RDWR)


class Listener():
    """An asynchronous socket listener"""
    def __init__(self, port):
        self._s = socket.socket()
        self._port = port

    def listen(self):
        """
        Bind the listener to a port. Return True on success, else return False.
        """
        try:
            self._s.bind(('0.0.0.0', self._port))
            self._s.listen(10)
        except OSError:
            return False
        else:
            return True

    @asyncio.coroutine
    def accept(self):
        """Return the next pending connection or None in case of error."""
        def func():
            try:
                return self._s.accept()
            except OSError:
                return None
        loop = asyncio.get_event_loop()
        result = yield from loop.run_in_executor(None, func)
        if result:
            s, (host, port) = result
            return Connection(ipv6(host), port, s)

    def shutdown(self):
        """Close the socket and terminate a pending accept call."""
        self._s.shutdown(socket.SHUT_RDWR)
