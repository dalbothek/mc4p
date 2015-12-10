# -*- coding: utf-8 -*-

# This source file is part of mc4p,
# the Minecraft Portable Protocol-Parsing Proxy.

# This program is free software. It comes without any warranty, to
# the extent permitted by applicable law. You can redistribute it
# and/or modify it under the terms of the Do What The Fuck You Want
# To Public License, Version 2, as published by Sam Hocevar. See
# http://www.wtfpl.net/txt/copying/ for more details

from __future__ import division
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import logging
import collections
import struct
import zlib

from mc4p import protocol
from mc4p import util
from mc4p import encryption

logger = logging.getLogger("stream")

BUFFER_SIZE = 1024 * 1024 * 64


class PacketStream(object):
    def __init__(self, direction, version=0):
        self.protocol = protocol.get_protocol_version(version)
        self.context = self.protocol.directions[direction].handshake
        self.partner = None
        self._cipher = None
        self._compression_threshold = None

    @property
    def compression_threshold(self):
        return self._compression_threshold

    @compression_threshold.setter
    def compression_threshold(self, threshold):
        self._compression_threshold = threshold
        if self.partner:
            self.partner._compression_threshold = threshold

    def pair(self, stream):
        self.partner = stream
        stream.partner = self

    def change_context(self, context):
        self.context = context
        self.protocol = context.protocol
        logger.debug("Switching state to %s" % context)
        if self.partner:
            self.partner.context = context.protocol.directions[
                self.partner.context.direction
            ].states[context.state]
            self.partner.protocol = context.protocol

    def enable_encryption(self, shared_secret):
        self._cipher = encryption.AES128CFB8(shared_secret)


class BufferedPacketInputStream(PacketStream):
    def __init__(self, direction, version=0):
        super(BufferedPacketInputStream, self).__init__(direction, version)
        self.input_buffer = memoryview(bytearray(BUFFER_SIZE))
        self.output_buffer = self.input_buffer
        self.write_position = 0
        self.read_position = 0
        self.last_boundary = 0
        self.buffer_views = collections.deque()

    def enable_encryption(self, shared_secret):
        super(BufferedPacketInputStream, self).enable_encryption(shared_secret)
        assert self.read_position == self.write_position
        self.output_buffer = memoryview(bytearray(BUFFER_SIZE))

    def write_buffer(self):
        if self.last_boundary > self.write_position:
            limit = self.last_boundary
        else:
            limit = BUFFER_SIZE
        if limit == self.write_position:
            raise IOError("Buffer overflow")
        return self.input_buffer[self.write_position:limit]

    def bytes_available(self):
        if self.write_position >= self.read_position:
            return self.write_position - self.read_position
        else:
            return BUFFER_SIZE - self.read_position + self.write_position

    def added_bytes(self, n):
        """Move the write position forward by n bytes"""
        pos = self.write_position
        while self.buffer_views:
            head = self.buffer_views[0]
            if 0 <= head.offset - pos < n:
                self.buffer_views.popleft().expired = True
            else:
                break

        if self._cipher is not None:
            # TODO: There has to be a way to do this without copying the
            # data first
            data = self._cipher.decrypt(
                self.input_buffer[pos:pos + n].tobytes()
            )
            self.output_buffer[pos:pos + n] = data

        self.write_position += n
        if self.write_position >= BUFFER_SIZE:
            self.write_position = 0

    def add_bytes(self, bytes):
        """Convenience function to add bytes to the buffer"""
        self.write_buffer()[:len(bytes)] = bytes
        self.added_bytes(len(bytes))

    def read_packet(self):
        length = self.read_varint()
        if self.compression_threshold is not None:
            uncompressed_length, varint_length = self.read_varint(True)
            length -= varint_length
        else:
            uncompressed_length = 0

        data = self.get_data(length)
        if uncompressed_length > 0:
            data = CompressedData(data, uncompressed_length)

        packet = self.context.read_packet(data)
        new_context = self.context.handle_packet(packet, self)
        if new_context:
            self.change_context(new_context)
        return packet

    def read_packets(self):
        try:
            while True:
                yield self.read_packet()
        except PartialPacketException:
            pass

    def read_varint(self, return_length=False):
        value = 0
        bytes_available = self.bytes_available()
        for i in range(5):
            if i >= bytes_available:
                raise self.partial_packet()
            b, = struct.unpack(b"B", self.output_buffer[self.read_position])
            self.read_position = (self.read_position + 1) % BUFFER_SIZE
            value |= (b & 0x7F) << 7 * i
            if not b & 0x80:
                if return_length:
                    return value, i + 1
                else:
                    return value
        raise IOError("Encountered varint longer than 5 bytes")

    def get_data(self, n):
        if n > self.bytes_available():
            raise self.partial_packet()
        view = BufferView(self.output_buffer, self.read_position, n)
        self.buffer_views.append(view)
        self.read_position = (self.read_position + n) % BUFFER_SIZE
        self.last_boundary = self.read_position
        return view

    def partial_packet(self):
        self.read_position = self.last_boundary
        return PartialPacketException()


class PacketOutputStream(PacketStream):
    def __init__(self, direction, version=0):
        super(PacketOutputStream, self).__init__(direction, version)
        self.encrypted = False
        self.compressed = False

    def emit(self, packet):
        data = packet._emit(self.compression_threshold)

        new_context = self.context.handle_packet(packet, self)
        if new_context:
            self.change_context(new_context)

        if self._cipher is not None:
            data = self._cipher.encrypt(data.tobytes())

        return data


class PartialPacketException(Exception):
    pass


class BufferView(protocol.PacketData):
    def __init__(self, bfr, offset, length):
        self.buffer = bfr
        self.offset = offset
        self.length = length
        self.expired = False
        self.read_position = 0

    def read(self):
        if self.expired:
            raise IOError("The requested data is no longer available")
        limit = min(self.offset + self.length, BUFFER_SIZE)
        data = self.buffer[self.offset:limit]
        if self.offset + self.length > BUFFER_SIZE:
            logger.debug("Rewinding buffer")
            limit = self.offset + self.length - BUFFER_SIZE
            data = util.CombinedMemoryView(data, self.buffer[:limit])
        return data

    def read_bytes(self, n=None):
        if self.expired:
            raise IOError("The requested data is no longer available")
        if n is None:
            n = self.length - self.read_position
        elif self.length < self.read_position + n:
            raise IOError("Buffer underflow")
        pos = self.read_position + self.offset
        data = self.buffer[pos:pos + n]
        if len(data) < n:
            data = util.CombinedMemoryView(
                data, self.buffer[:pos + n - BUFFER_SIZE]
            )
        self.read_position += n
        return data

    def __len__(self):
        return self.length


class CompressedData(protocol.PacketData):
    CHUNK_SIZE = 128

    def __init__(self, data, uncompressed_length):
        self.data = data
        self.length = uncompressed_length

        self.read_position = 0
        self.decompressed_data = util.CombinedMemoryView()
        self.decompress_object = zlib.decompressobj()

    def decompress(self, length):
        while length + self.read_position > len(self.decompressed_data):
            limit = min(self.CHUNK_SIZE,
                        len(self.data) - self.data.read_position)

            if limit <= 0:
                raise IOError("Buffer underflow")

            chunk = self.data.read_bytes(limit).tobytes()

            if self.decompress_object.unconsumed_tail:
                chunk = self.decompress_object.unconsumed_tail + chunk

            self.decompressed_data.append(
                self.decompress_object.decompress(chunk)
            )

    def read(self):
        self.decompress(self.length - self.read_position)
        return self.decompressed_data

    def read_bytes(self, n=None):
        if n is None:
            n = self.length - self.read_position
        elif self.length < self.read_position + n:
            raise IOError("Buffer underflow")
        self.decompress(n)
        original_position = self.read_position
        self.read_position += n
        return self.decompressed_data[original_position:self.read_position]

    def read_compressed(self):
        return self.data.read()

    def __len__(self):
        return self.length


if __name__ == "__main__":
    stream = BufferedPacketInputStream(protocol.Direction.server_bound)
    data = b"11 00 05 0b 31 39 32 2e 31 36 38 2e 30 2e 31 88 dc 01 01 00"
    data = data.replace(" ", "")
    bfr = stream.write_buffer()
    for i in range(len(data) // 2):
        bfr[i] = chr(int(data[i * 2] + data[i * 2 + 1], 16))
    stream.added_bytes(len(data) // 2)

    for packet in stream.read_packets():
        print(packet)
        for field in packet._fields:
            print(field, getattr(packet, field))
        print()
