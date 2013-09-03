# -*- coding: utf-8 -*-

# This source file is part of mc4p,
# the Minecraft Portable Protocol-Parsing Proxy.
#
# Copyright (C) 2011 Matthew J. McGill, Simon Marti

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v2 as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import re
import struct
import inspect
import collections

from mc4p import logger


class Protocol(dict):
    """Collection of multiple protocol versions"""
    def version(self, version):
        return ProtocolVersion(version, self)

    def __getitem__(self, version):
        assert isinstance(version, int)
        while version not in self and version > 0:
            version -= 1
        return super(Protocol, self).__getitem__(version)

    def _register_version(self, protocol_version):
        self[protocol_version.version] = protocol_version

    def __str__(self):
        return "\n\n".join(str(version) for version in self.itervalues())


class ProtocolVersion(list):
    def __init__(self, version, protocol=None):
        self.version = version
        super(ProtocolVersion, self).__init__([None] * 256)
        self.protocol = protocol

    def parse_message(self, stream, side):
        message_id = UnsignedByte.parse(stream)
        logger.debug("%s trying to parse message type %x" % (side, message_id))
        message = self[message_id]
        if message is None:
            raise self.UnsupportedPacketException(message_id)
        if not message._accept_from(side):
            raise self.WrongDirectionException(message, side)
        return message(stream, side)

    def __enter__(self):
        pass

    def __exit__(self, *args):
        """Captures all defined messages"""
        potential_messages = inspect.currentframe().f_back.f_locals
        for message in potential_messages.itervalues():
            if (inspect.isclass(message) and
                    issubclass(message, Message) and
                    message not in (Message, ServerMessage, ClientMessage)):
                message._do_magic()
                self[message.id] = message
        if self.protocol is not None:
            self.protocol._register_version(self)

    def __str__(self):
        return "\n".join((
            "Protocol version %s" % self.version,
            "-------------------",
            "\n\n".join(msg._str() for msg in self if msg)
        ))

    class UnsupportedPacketException(Exception):
        def __init__(self, message_id):
            super(ProtocolVersion.UnsupportedPacketException, self).__init__(
                "Unsupported packet id 0x%x" % message_id
            )
            self.message_id = message_id

    class WrongDirectionException(Exception):
        def __init__(self, message, side):
            correct_side = "server" if side == "client" else "client"
            super(ProtocolVersion.WrongDirectionException, self).__init__(
                "Received %s-only packet 0x%02x %s from %s" %
                (correct_side, message.id, message._name, side)
            )
            self.message = message
            self.side = side


class Message(object):
    _NAME_PATTERN = re.compile("(.)([A-Z])")
    id = None

    def __init__(self, stream=None, side=None, **kwargs):
        self._side = side
        if stream is not None and kwargs:
            raise TypeError("Unexpected argument combination")
        for name, field in self._fields.iteritems():
            if stream is not None:
                setattr(self, name, field.parse(stream, self))
            else:
                setattr(self, name, kwargs.get(name))
        if stream is not None:
            self._raw_bytes = stream.packet_finished()

    def emit(self):
        for name, field in self._fields.iteritems():
            field.prepare(getattr(self, name), self)
        return (struct.pack(">B", self.id) +
                "".join(field.emit(getattr(self, name), self)
                        for name, field in self._fields.iteritems()))

    def __str__(self):
        if self._fields:
            fields = "\n".join(
                "  %s (%s): %s" %
                (name, field, field.format(getattr(self, name)))
                for name, field in self._fields.iteritems()
            )
        else:
            fields = "  -- empty --"
        if self._side == "client":
            direction = "Client -> Server "
        elif self._side == "server":
            direction = "Server -> Client "
        else:
            direction = ""
        return "\n".join((
            "%s0x%02x %s" % (direction, self.id, self._name),
            fields
        ))

    @classmethod
    def _accept_from(cls, side):
        return True

    @classmethod
    def _do_magic(cls):
        cls._name = cls._NAME_PATTERN.sub(
            lambda g: "%s %s" % (g.group(1), g.group(2)), cls.__name__
        )
        cls._fields = collections.OrderedDict(sorted(
            ((name, field) for name, field in cls.__dict__.iteritems()
             if isinstance(field, MessageField)),
            key=lambda i: i[1]._order_id
        ))

    @classmethod
    def _str(cls):
        if cls._fields:
            fields = "\n".join(
                "  %s (%s)" % (name, field)
                for name, field in cls._fields.iteritems()
            )
        else:
            fields = "  -- empty --"
        return "\n".join((
            "0x%02x %s" % (cls.id, cls._name),
            fields
        ))


class ClientMessage(Message):
    """Message sent from client to server"""
    @classmethod
    def _accept_from(cls, side):
        return side == "client"


class ServerMessage(Message):
    """Message sent from server to client"""
    @classmethod
    def _accept_from(cls, side):
        return side == "server"


class MessageField(object):
    _NEXT_ID = 1

    def __init__(self):
        self._order_id = MessageField._NEXT_ID
        MessageField._NEXT_ID += 1

    @classmethod
    def parse(cls, stream, message):
        return None

    @classmethod
    def prepare(cls, value, message):
        """Used to set stray length fields"""
        pass

    @classmethod
    def emit(self, value, message):
        return ""

    def format(self, value):
        return str(value)

    @classmethod
    def _parse_subfield(cls, field, stream, message):
        if isinstance(field, MessageField):
            return field.parse(stream, message)
        elif isinstance(field, basestring):
            return getattr(message, field)
        elif isinstance(field, dict):
            return collections.OrderedDict(
                (key, cls._parse_subfield(subfield, stream, message))
                for key, subfield in field.iteritems()
            )
        else:
            raise NotImplementedError

    @classmethod
    def _emit_subfield(cls, field, value, message):
        if isinstance(field, MessageField):
            return field.emit(value, message)
        elif isinstance(field, basestring):
            return ""
        elif isinstance(field, dict):
            return "".join(
                cls._emit_subfield(subfield, value[name], message)
                for name, subfield in field.iteritems()
            )
        else:
            raise NotImplementedError

    @classmethod
    def _set_subfield(cls, field, value, message):
        if isinstance(field, basestring):
            setattr(message, field, value)

    def __str__(self):
        return self.__class__.__name__


def simple_type_field(name, format):
    format = ">" + format
    length = struct.calcsize(format)

    class SimpleType(MessageField):
        @classmethod
        def parse(cls, stream, message=None):
            return struct.unpack(format, stream.read(length))[0]

        @classmethod
        def emit(cls, value, message=None):
            return struct.pack(format, value)

    SimpleType.__name__ = name
    return SimpleType


class Conditional(MessageField):
    def __init__(self, field, condition):
        self._field = field
        self.condition = condition
        super(Conditional, self).__init__()

    def parse(self, stream, message):
        if not self.condition(message):
            return None
        return self._parse_subfield(self._field, stream, message)

    def emit(self, value, message):
        if not self.condition(message):
            return ""
        return self._emit_subfield(self._field, value, message)


class List(MessageField):
    def __init__(self, field, size):
        self._size = size
        self._field = field
        super(List, self).__init__()

    def parse(self, stream, message=None):
        return [
            self._parse_subfield(self._field, stream, message)
            for i in range(self._parse_subfield(self._size, stream, message))
        ]

    def emit(self, value, message=None):
        return (self._emit_subfield(self._size, len(value), message) +
                "".join(self._emit_subfield(self._field, entry, message)
                        for entry in value))


class Dict(MessageField):
    def __init__(self, key, value, size):
        self._size = size
        self._key = key
        self._value = value
        super(Dict, self).__init__()

    def parse(self, stream, message=None):
        return collections.OrderedDict(
            (self._parse_subfield(self._key, stream, message),
             self._parse_subfield(self._value, stream, message))
            for i in range(self._parse_subfield(self._size, stream, message))
        )

    def emit(self, value, message=None):
        return (self._emit_subfield(self._size, len(value), message) +
                "".join(self._emit_subfield(self._key, key, message) +
                        self._emit_subfield(self._value, entry, message)
                        for key, entry in value.iteritems()))

    def format(self, value):
        return str(dict(value))


class Object(MessageField):
    def __init__(self, **fields):
        self._fields = collections.OrderedDict(
            sorted(fields.iteritems(), key=lambda f: f[1]._order_id)
        )

    def parse(self, stream, message=None):
        return self.ObjectValue(**dict(
            (name, field.parse(stream, message))
            for name, field in self._fields.iteritems()
        ))

    def emit(self, value, message=None):
        return "".join(
            field.emit(getattr(value, name), message)
            for name, field in self._fields.iteritems()
        )

    class ObjectValue(object):
        def __init__(self, **kwargs):
            for attr, value in kwargs.iteritems():
                setattr(self, attr, value)
            self._dict = kwargs

        def __repr__(self):
            return str(self._dict)


Byte = simple_type_field("Byte", "b")
UnsignedByte = simple_type_field("UnsignedByte", "B")
Short = simple_type_field("Short", "h")
Int = simple_type_field("Int", "i")
Float = simple_type_field("Float", "f")
Double = simple_type_field("Double", "d")
Long = simple_type_field("Long", "q")


class Bool(Byte):
    @classmethod
    def parse(cls, stream, message):
        return super(Bool, cls).parse(stream) == 1


class String(MessageField):
    @classmethod
    def parse(cls, stream, message=None):
        return unicode(stream.read(2 * Short.parse(stream)),
                       encoding="utf-16-be")

    @classmethod
    def emit(cls, value, message=None):
        return Short.emit(len(value)) + value.encode("utf-16-be")

    def format(self, value):
        return value.encode("utf8")


class Data(MessageField):
    def __init__(self, size):
        self._size = size
        super(Data, self).__init__()

    def parse(self, stream, message=None):
        return stream.read(self._parse_subfield(self._size, stream, message))

    def emit(self, value, message=None):
        return self._emit_subfield(self._size, len(value), message) + value

    def format(self, value):
        if value is None:
            return "None" + str(self._size)
        return "<Data: %d bytes>" % len(value)
        return " ".join("%02x" % ord(c) for c in value)


class ItemStack(MessageField):
    @classmethod
    def parse(cls, stream, message=None):
        item_id = Short.parse(stream)
        if item_id == -1:
            return None
        item = cls.ItemStack(
            id=item_id,
            count=Byte.parse(stream),
            uses=Short.parse(stream)
        )
        nbt_size = Short.parse(stream)
        item.nbt_data = stream.read(nbt_size) if nbt_size > 0 else None
        return item

    @classmethod
    def emit(cls, value, message=None):
        if value is None:
            return Short.emit(-1)
        return "".join((
            Short.emit(value.id),
            Byte.emit(value.count),
            Short.emit(value.uses),
            Short.emit(len(value.nbt_data) if value.nbt_data else -1),
            value.nbt_data if value.nbt_data else ""
        ))

    class ItemStack(Object.ObjectValue):
        def __str__(self):
            return str(self.id)


class Metadata(MessageField):
    FIELD_TYPES = [
        Byte,
        Short,
        Int,
        Float,
        String,
        ItemStack
    ]

    @classmethod
    def _key_generator(cls, stream):
        while True:
            key = UnsignedByte.parse(stream)
            if key == 127:
                return
            if key >> 5 >= 6:
                raise Exception("Invalid Metadata type: %d" % (key >> 5))
            yield key

    @classmethod
    def parse(cls, stream, message=None):
        return [{
            'index': key & 0x1f,
            'type': key >> 5,
            'value': cls.FIELD_TYPES[key >> 5].parse(stream)
        } for key in cls._key_generator(stream)]

    @classmethod
    def emit(cls, value, message=None):
        return "".join(
            UnsignedByte.emit(item['index'] | item['type'] << 5) +
            cls.FIELD_TYPES[item['type']].emit(item['value'])
            for item in value
        ) + "\x7f"
