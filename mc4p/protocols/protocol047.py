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

from mc4p.protocol import *
from mc4p.parsing import *


protocol = Protocol(47, incomplete=True)


with protocol.server_bound.handshake:
    class Handshake(Packet):
        id = 0x00
        version = VarInt()
        host = String()
        port = UnsignedShort()
        state = VarInt()


with protocol.server_bound.status:
    class Request(Packet):
        id = 0x00

    class Ping(Packet):
        id = 0x01
        time = Long()


with protocol.client_bound.status:
    class Response(Packet):
        id = 0x00
        status = Json()

    class Ping(Packet):
        id = 0x01
        time = Long()


with protocol.server_bound.login:
    class LoginStart(Packet):
        id = 0x00
        name = String()

    class EncryptionResponse(Packet):
        id = 0x01
        shared_secret = Data(VarInt())
        verify_token = Data(VarInt())


with protocol.client_bound.login:
    class Disconnect(Packet):
        id = 0x00
        reason = Chat()

    class EncryptionRequest(Packet):
        id = 0x01
        server_id = String()
        public_key = Data(VarInt())
        verify_token = Data(VarInt())

    class LoginSuccess(Packet):
        id = 0x02
        uuid = String()
        username = String()

    class SetCompression(Packet):
        id = 0x03
        threshold = VarInt()


with protocol.server_bound.play:
    class KeepAlive(Packet):
        id = 0x00
        keep_alive_id = VarInt()

    class ChatMessage(Packet):
        id = 0x01
        message = String()

    class PlayerPositionAndLook(Packet):
        id = 0x06
        x = Double()
        y = Double()
        z = Double()
        yaw = Float()
        pitch = Float()
        on_ground = Bool()

    class ClientStatus(Packet):
        id = 0x16
        action_id = VarInt()

    class PluginMessage(Packet):
        id = 0x17
        channel = String()
        data = Data()

        def parse_as_string(self):
            return String.parse(PacketData(self.data))


with protocol.client_bound.play:
    class KeepAlive(Packet):
        id = 0x00
        keep_alive_id = VarInt()

    class JoinGame(Packet):
        id = 0x01
        entity_id = Int()
        gamemode = UnsignedByte()
        dimension = Byte()
        difficulty = UnsignedByte()
        max_players = UnsignedByte()
        level_type = String()
        reduced_debug_info = Bool()

    class ChatMessage(Packet):
        id = 0x02
        message = Chat()
        position = Byte()

    class PlayerPositionAndLook(Packet):
        id = 0x08
        x = Double()
        y = Double()
        z = Double()
        yaw = Float()
        pitch = Float()
        flags = Byte()

    class ChunkData(Packet):
        id = 0x21
        chunk_x = Int()
        chunk_z = Int()
        ground_up_continous = Bool()
        primary_bit_mask = UnsignedShort()
        data = Data(VarInt())

    class MapChunkBulk(Packet):
        id = 0x26
        data = Data()

    class UpdateSign(Packet):
        id = 0x33
        location = Position()
        line_1 = Chat()
        line_2 = Chat()
        line_3 = Chat()
        line_4 = Chat()

    class PlayerAbilities(Packet):
        id = 0x39
        flags = Byte()
        flying_speed = Float()
        field_of_view_modifier = Float()

    class Teams(Packet):
        id = 0x3e
        team_name = String()
        mode = Byte()
        data = Data()

    class PluginMessage(Packet):
        id = 0x3f
        channel = String()
        data = Data()

        def parse_as_string(self):
            return String.parse(PacketData(self.data))

    class Disconnect(Packet):
        id = 0x40
        reason = Chat()

    class SetCompression(Packet):
        id = 0x46
        threshold = VarInt()


@protocol.packet_handler(protocol.server_bound.handshake.Handshake)
def handle_handshake(packet, packet_stream):
    protocol = get_protocol_version(packet.version)
    return protocol.server_bound.states[State[packet.state]]


@protocol.packet_handler(protocol.client_bound.login.LoginSuccess)
def handle_login_success(packet, packet_stream):
    return protocol.client_bound.play


@protocol.packet_handler(protocol.client_bound.play.SetCompression)
@protocol.packet_handler(protocol.client_bound.login.SetCompression)
def handle_set_compression(packet, packet_stream):
    packet_stream.compression_threshold = packet.threshold
