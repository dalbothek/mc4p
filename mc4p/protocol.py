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
import re
import collections
import zlib
import inspect
import importlib
import traceback

from mc4p import parsing
from mc4p import util


logger = logging.getLogger("protocol")


MAX_PROTOCOL_VERSION = 109


class Protocol(object):
    def __init__(self, version, incomplete=False):
        self.version = version
        self.incomplete = incomplete
        self.directions = dict(
            (direction, ProtocolDirectionContext(direction, self))
            for direction in Direction
        )
        for name, direction in self.directions.iteritems():
            setattr(self, name, direction)

    def packet_handler(self, packet):
        def decorator(f):
            packet._context.register_packet_handler(packet, f)
            return f
        return decorator


class ProtocolDirectionContext(object):
    def __init__(self, direction, protocol):
        self.protocol = protocol
        self.direction = direction
        self.states = dict(
            (state, ProtocolStateContext(state, direction, protocol))
            for state in State
        )
        for name, state in self.states.iteritems():
            setattr(self, name, state)


class ProtocolStateContext(object):
    def __init__(self, state, direction, protocol):
        self.protocol = protocol
        self.direction = direction
        self.state = state
        self.packets = {}
        self.handlers = {}

    # Please look away for a second

    def __enter__(self):
        definitions = inspect.currentframe().f_back.f_locals
        for name, value in definitions.items():
            if (inspect.isclass(value) and issubclass(value, Packet) and
                    value != Packet):
                del definitions[name]

    def __exit__(self, *args):
        potential_packets = inspect.currentframe().f_back.f_locals
        for packet in potential_packets.itervalues():
            if (inspect.isclass(packet) and issubclass(packet, Packet) and
                    packet != Packet):
                packet._do_magic(self)
                self.packets[packet.id] = packet
                setattr(self, packet.__name__, packet)

    # Okay, you may look again

    def read_packet(self, data, strict_protocol=True):
        id_ = parsing.VarInt.parse(data)
        if id_ not in self.packets:
            if not strict_protocol or self.protocol.incomplete:
                return UnknownPacket(data, id_=id_)
            else:
                raise InvalidPacketException(self, id_)
        return self.packets[id_](_data=data, _strict_protocol=strict_protocol)

    def register_packet_handler(self, packet, handler):
        self.handlers.setdefault(packet, []).append(handler)

    def handle_packet(self, packet, packet_stream):
        handlers = self.handlers.get(packet.__class__)
        if handlers:
            contexts = [handler(packet, packet_stream) for handler in handlers]
            contexts = [context for context in contexts if context]
            if contexts:
                if len(contexts) > 1:
                    raise Exception("More than one new protocol context set")
                return contexts[0]

    def __repr__(self):
        return "<ProtocolContext dir:%s state:%s version:%d>" % (
            self.direction, self.state, self.protocol.version
        )


class InvalidPacketException(Exception):
    def __init__(self, context, id_):
        super(InvalidPacketException, self).__init__(
            "Invalid packet id: 0x%02x (dir: %s, state: %s, version: %d)" %
            (id_, context.direction, context.state, context.protocol.version)
        )


class UpgradedProtocol(object):
    def __init__(self, protocol, version):
        self.original_protocol = protocol
        self.version = version
        self.incomplete = True

        self.directions = dict(
            (direction, UpgradedProtocolDirectionContext(self, context))
            for direction, context in protocol.directions.iteritems()
        )

        for name, direction in self.directions.iteritems():
            setattr(self, name, direction)


class UpgradedProtocolDirectionContext(object):
    def __init__(self, protocol, direction_context):
        self.protocol = protocol
        self.direction = direction_context.direction

        self.states = dict(
            (state, UpgradedProtocolStateContext(protocol, state_context))
            for state, state_context in direction_context.states.iteritems()
        )

        for name, state in self.states.iteritems():
            setattr(self, name, state)


class UpgradedProtocolStateContext(object):
    def __init__(self, protocol, state_context):
        self.protocol = protocol
        self.direction = state_context.direction
        self.state = state_context.state
        self.original_state_context = state_context

        for packet in state_context.packets.itervalues():
            setattr(self, packet.__name__, packet)

    def read_packet(self, data):
        return self.original_state_context.read_packet(
            data, strict_protocol=False
        )

    def handle_packet(self, packet, packet_stream):
        new_context = self.original_state_context.handle_packet(packet,
                                                                packet_stream)

        if new_context:
            return (self.protocol.directions[new_context.direction]
                                 .states[new_context.state])

    def __repr__(self):
        return ("<UpgradedProtocolContext dir:%s state:%s "
                "version:%d (upgraded from %d)>") % (
            self.direction, self.state, self.protocol.version,
            self.protocol.original_protocol.version)


class Packet(object):
    _NAME_PATTERN = re.compile("(.)([A-Z])")

    def __init__(self, _data=None, _strict_protocol=True,
                 _ignore_extra_fields=False, **fields):
        self._strict_protocol = _strict_protocol
        self._invalid = False
        self._parse_error = False
        self._parse_traceback = False

        if _data:
            self._parsed = False
            self._data = _data
            self._dirty = False
        else:
            self._parsed = True
            self._dirty = True
            for name, value in fields.iteritems():
                if name in self._fields:
                    setattr(self, name, value)
                elif not _ignore_extra_fields:
                    raise ValueError("%s has no field %s" % (self, name))
            for name, field in self._fields.iteritems():
                if name not in fields:
                    setattr(self, name, None)

    def _emit(self, compression_threshold=None):
        if self._dirty:
            self._encode()

        if compression_threshold:
            if len(self._data) >= compression_threshold:
                data = self._data.read_compressed()
                uncompressed_length = parsing.VarInt.emit(len(self._data))
            else:
                data = self._data.read()
                uncompressed_length = parsing.VarInt.emit(0)
            return util.CombinedMemoryView(
                parsing.VarInt.emit(len(data) + len(uncompressed_length)),
                uncompressed_length,
                data
            )
        else:
            return util.CombinedMemoryView(
                parsing.VarInt.emit(len(self._data)),
                self._data.read()
            )

    # Only completely parse a packet if necessary
    def __getattribute__(self, attr):
        field = super(Packet, self).__getattribute__(attr)
        if attr[0] == "_" or self._parsed or attr not in self._fields:
            return field
        self._parse()
        return super(Packet, self).__getattribute__(attr)

    def __setattr__(self, attr, value):
        if attr[0] != "_":
            if not self._parsed:
                self._parse()
            self._dirty = True
        super(Packet, self).__setattr__(attr, value)

    def _parse(self):
        # We're setting _parsed prematurely so __getattribute__ and __setattr__
        # won't cause an infinite recursion loop
        self._parsed = True

        for name, field in self._fields.iteritems():
            try:
                setattr(self, name, field.parse(self._data, self))
            except Exception as e:
                if self._strict_protocol:
                    raise
                else:
                    self._invalid = True
                    self._parse_error = e
                    self._parse_traceback = traceback.format_exc()
            if self._invalid:
                setattr(self, name, None)

        self._dirty = False

    def _encode(self):
        self._data = PacketData(util.CombinedMemoryView(
            parsing.VarInt.emit(self.id),
            *tuple(
                field.emit(getattr(self, name), self)
                for name, field in self._fields.iteritems()
            )
        ))
        self._dirty = False

    def __repr__(self):
        return "<%s Packet>" % self._name

    def __unicode__(self):
        if not self._parsed:
            self._parse()

        if self._invalid:
            return "Invalid %s Packet\n%s" % (self._name,
                                              self._parse_traceback)
        else:
            lines = ["%s Packet" % self._name]

            for name, field in self._fields.iteritems():
                value = getattr(self, name)
                if value:
                    value = field.format(value)
                lines.append(
                    "  %s: %s" % (name, value)
                )

        return "\n".join(lines)

    def __str__(self):
        return unicode(self).encode("utf8")

    def _show(self):
        print(self)

    @classmethod
    def _do_magic(cls, context):
        cls._state = context.state
        cls._direction = context.direction
        cls._context = context
        cls._name = cls._NAME_PATTERN.sub(
            lambda g: "%s %s" % (g.group(1), g.group(2)), cls.__name__
        )
        cls._fields = collections.OrderedDict(sorted(
            ((name, field) for name, field in cls.__dict__.iteritems()
             if isinstance(field, parsing.Field)),
            key=lambda i: i[1]._order_id
        ))


class PacketData(object):
    def __init__(self, data):
        if isinstance(data, basestring):
            data = memoryview(data)
        self.data = data
        self.length = len(data)
        self.read_position = 0

    def read(self):
        return self.data

    def read_bytes(self, n=None):
        if n is None:
            n = self.length - self.read_position
        elif self.length < self.read_position + n:
            raise IOError("Buffer underflow")
        data = self.data[self.read_position:self.read_position + n]
        self.read_position += n
        return data

    def read_compressed(self):
        return memoryview(zlib.compress(self.read().tobytes()))

    def __len__(self):
        return self.length


class UnknownPacket(Packet):
    _state = None
    _direction = None
    _name = "Unknown"
    _fields = {}

    def __init__(self, data, id_=None):
        super(UnknownPacket, self).__init__(data)
        self._id = id_

    @property
    def id(self):
        return self._id

    def __setattr__(self, attr, value):
        if attr[0] != "_":
            raise Exception("Unknown packets are immutable")
        else:
            super(UnknownPacket, self).__setattr__(attr, value)

    def __unicode__(self):
        if self.id is not None:
            return ("Unknown Packet (id: 0x%02x length:%d)" %
                    (self.id, len(self._data)))
        else:
            return "Unknown Packet"

    def _show(self):
        print(self)


_PROTOCOL_CACHE = {}
_UPGRADED_PROTOCOL_CACHE = {}


def get_protocol_version(version, upgrade_protocol=True,
                         original_protocol_version=None):
    if version in _PROTOCOL_CACHE:
        return _PROTOCOL_CACHE[version]
    elif (upgrade_protocol and version in _UPGRADED_PROTOCOL_CACHE and
            original_protocol_version is None):
        return _UPGRADED_PROTOCOL_CACHE[version]
    else:
        try:
            module = importlib.import_module(
                "mc4p.protocols.protocol%03d" % version
            )
        except ImportError:
            if not upgrade_protocol or version <= 0:
                raise UnknownProtocolVersion(version)
            else:
                protocol = get_protocol_version(
                    version - 1, upgrade_protocol=True,
                    original_protocol_version=(original_protocol_version or
                                               version)
                )
                if original_protocol_version is None:
                    protocol = UpgradedProtocol(protocol, version)
                    _UPGRADED_PROTOCOL_CACHE[version] = protocol
                return protocol
        else:
            _PROTOCOL_CACHE[version] = module.protocol
            return module.protocol


def get_latest_protocol():
    return get_protocol_version(MAX_PROTOCOL_VERSION)


class UnknownProtocolVersion(Exception):
    def __init__(self, version):
        super(UnknownProtocolVersion, self).__init__(
            "Unknown protocol version: %d" % version
        )


Direction = util.StringEnum("server_bound", "client_bound")
State = util.StringEnum("handshake", "status", "login", "play")


def __opposite_direction(direction):
    if direction == Direction.client_bound:
        return Direction.server_bound
    else:
        return Direction.client_bound


Direction.opposite_direction = __opposite_direction
