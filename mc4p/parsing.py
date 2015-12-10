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
import json

from mc4p import util


logger = logging.getLogger("parsing")


class Field(object):
    _NEXT_ID = 1

    def __init__(self):
        self._order_id = Field._NEXT_ID
        Field._NEXT_ID += 1

    @classmethod
    def parse(cls, data, packet):
        return None

    @classmethod
    def prepare(cls, data, packet):
        """Used to set stray length fields"""
        pass

    @classmethod
    def emit(cls, value, message):
        return b""

    def format(self, value):
        return str(value)

    @classmethod
    def _parse_subfield(cls, field, data, packet):
        if isinstance(field, Field):
            return field.parse(data, packet)
        elif isinstance(field, basestring):
            return getattr(packet, field)
        elif isinstance(field, dict):
            return collections.OrderedDict(
                (key, cls._parse_subfield(subfield, data, packet))
                for key, subfield in field.iteritems()
            )
        else:
            raise NotImplementedError

    @classmethod
    def _emit_subfield(cls, field, value, packet):
        if isinstance(field, Field):
            return field.emit(value, packet)
        elif isinstance(field, basestring):
            return ""
        elif isinstance(field, dict):
            return "".join(
                cls._emit_subfield(subfield, value[name], packet)
                for name, subfield in field.iteritems()
            )
        else:
            raise NotImplementedError

    @classmethod
    def _set_subfield(cls, field, value, packet):
        if isinstance(field, basestring):
            setattr(packet, field, value)

    def __str__(self):
        return self.__class__.__name__


def simple_type_field(name, format):
    format = b">" + format
    length = struct.calcsize(format)

    class SimpleType(Field):
        @classmethod
        def parse(cls, data, packet=None):
            return struct.unpack(format, data.read_bytes(length).tobytes())[0]

        @classmethod
        def emit(cls, value, packet=None):
            return struct.pack(format, value)

    SimpleType.__name__ = name
    return SimpleType


Byte = simple_type_field(b"Byte", b"b")
Short = simple_type_field(b"Short", b"h")
Int = simple_type_field(b"Int", b"i")
Long = simple_type_field(b"Long", b"q")
Float = simple_type_field(b"Float", b"f")
Double = simple_type_field(b"Double", b"d")

UnsignedByte = simple_type_field(b"UnsignedByte", b"B")
UnsignedShort = simple_type_field(b"UnsignedShort", b"H")
UnsignedInt = simple_type_field(b"UnsignedInt", b"I")
UnsignedLong = simple_type_field(b"UnsignedLong", b"Q")


class Bool(Field):
    @classmethod
    def parse(cls, data, packet=None):
        return struct.unpack(b"b", data.read_bytes(1).tobytes())[0] != 0

    @classmethod
    def emit(cls, value, packet=None):
        return struct.pack(b"b", 1 if value else 0)


class VarInt(Field):
    @classmethod
    def parse(cls, data, packet=None):
        value = 0
        for i in range(5):
            # ord() is about 3x as fast as struct.unpack() for single bytes
            b = ord(data.read_bytes(1).tobytes())
            value |= (b & 0x7F) << 7 * i
            if not b & 0x80:
                return value
        raise IOError("Encountered varint longer than 5 bytes")

    @classmethod
    def emit(cls, value, packet=None):
        return b"".join(
            struct.pack(
                b">B",
                (value >> i * 7) & 0x7f | (value >> (i + 1) * 7 > 0) << 7
            )
            for i in range(((value.bit_length() - 1) // 7 + 1) or 1)
        )


class String(Field):
    @classmethod
    def parse(cls, data, packet=None):
        return unicode(data.read_bytes(VarInt.parse(data)).tobytes(),
                       encoding="utf-8")

    @classmethod
    def emit(cls, value, packet=None):
        return VarInt.emit(len(value)) + value.encode("utf-8")

    def format(self, value):
        return value.encode("utf8")


class Json(Field):
    @classmethod
    def parse(cls, data, packet=None):
        return json.loads(String.parse(data, packet))

    @classmethod
    def emit(cls, value, packet=None):
        return String.emit(json.dumps(value), packet)


class Data(Field):
    def __init__(self, size=None):
        super(Data, self).__init__()
        self.size = size

    def parse(self, data, packet=None):
        if self.size is None:
            length = None
        else:
            length = self._parse_subfield(self.size, data, packet)
        return data.read_bytes(length)

    def emit(self, value, packet=None):
        if self.size is None:
            return value
        else:
            return util.CombinedMemoryView(
                self._emit_subfield(self.size, len(value), packet),
                value
            )

    def format(self, value):
        if value is None:
            return "None"
        return "<Data: %d bytes>" % len(value)
