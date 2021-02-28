# -*- coding: utf-8 -*-
import asyncio
from functools import cached_property
import secrets
import socket
import struct
import time
from typing import Union


def aiotraceroute(dest, port=33434, max_hops=30, timeout=1, packet_size=60):
    return _AsyncTraceroute(dest, port, max_hops, timeout, packet_size)


_wireformat_port = struct.Struct("!H")


class _AsyncTraceroute:
    def __init__(self, dest, port, max_hops, timeout, packet_size):
        assert isinstance(dest, str), "Expected attribute 'dest' to be str"
        assert isinstance(port, int), "Expected attribute 'port' to be int"
        assert isinstance(max_hops, int), "Expected attribute 'max_hops' to be int"
        assert isinstance(
            timeout,
            (int, float),
        ), "Expected attribute 'timeout' to be numeric"
        assert isinstance(
            packet_size, int
        ), "Expected attribute 'packet_size' to be int"

        try:
            socket.inet_aton(dest)
            self.dst_addr = dest
        except socket.error:
            self.dst_addr = socket.gethostbyname(dest)

        self.starting_port: int = port
        self.max_hops: int = max_hops
        self.timeout: Union[int, float] = timeout
        self.payload: bytes = secrets.token_bytes(packet_size)
        self._ttl: int = 1

        self._loop = asyncio.get_event_loop()
        self._queue = asyncio.Queue()
        self._rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self._tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._loop.add_reader(self._rx, self._handle_response)

    @property
    def src_port(self):
        return self._tx.getsockname()[1]

    @property
    def dst_port(self) -> int:
        return self.starting_port + self._ttl

    async def run(self):
        return [res async for res in self]

    def __iter__(self):
        raise RuntimeError("You need to use the syntax 'async for'")

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._ttl == self.max_hops:
            self._loop.remove_reader(self._rx)
            self._rx.close()
            self._tx.close()

            raise StopAsyncIteration

        self._ttl += 1
        next_addr = None

        try:
            self._tx.setsockopt(socket.SOL_IP, socket.IP_TTL, self._ttl)

            start = stop = time.perf_counter_ns()

            self._tx.sendto(self.payload, (self.dst_addr, self.dst_port))

            try:
                _, (next_addr, _) = await asyncio.wait_for(
                    self._queue.get(), self.timeout
                )
                stop = time.perf_counter_ns()

                if next_addr == self.dst_addr:
                    # Stop on next iteration
                    self.max_hops = self._ttl

                result = "success"
            except asyncio.TimeoutError:
                result = "timeout"

            return self._ttl, result, next_addr, (stop - start) // 1000
        except Exception as e:
            # Stop on next iteration
            self.max_hops = self._ttl

            return (self._ttl, repr(e), None, None)

    def _handle_response(self):
        payload, src = self._rx.recvfrom(4096)

        if self._should_handle_response(payload):
            self._queue.put_nowait((payload, src))

    def _should_handle_response(self, payload):
        # Nonce came back, handle packet
        if self.payload in payload:
            return True

        # If we don't get our unique payload back [1], we'll need to try and
        # match on the fields in the return IP & UDP payload.
        #
        # [1]: RFC1812 only mandates the first 8 bytes of the IP payload be
        # returned. Which in most cases is just the headers of the next protocol
        # (in our case UDP).

        same_dst_addr = socket.inet_aton(self.dst_addr) == payload[44:48]

        same_src_port = _wireformat_port.pack(self.src_port) == payload[48:50]
        same_dst_port = _wireformat_port.pack(self.dst_port) == payload[50:52]

        return same_src_port and same_dst_addr and same_dst_port
