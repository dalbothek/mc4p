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

from mc4p.parsing import *


protocol = Protocol()


### GENERIC MESSAGES - Independent of protocol version
with protocol.version(0):
    class MagicConstant(ClientMessage):
        id = 0x01

    class Handshake(ClientMessage):
        id = 0x02
        version = Byte()
        username = String()
        host = String()
        port = Int()

    class PluginMessage(Message):
        id = 0xfa
        channel = String()
        data = Data(Short())

    class ServerListPing(ClientMessage):
        id = 0xfe

    class Diconnect(Message):
        id = 0xff
        reason = String()


### VERSION 61 - Corresponds to 1.5.2
with protocol.version(61):
    class KeepAlive(Message):
        id = 0x00
        ping_id = Int()

    class Login(Message):
        id = 0x01
        eid = Int()
        level_type = String()
        game_mode = Byte()
        dimension = Byte()
        difficulty = Byte()
        unused = Byte()
        max_players = Byte()

    class ChatMessage(Message):
        id = 0x03
        message = String()

    class Time(ServerMessage):
        id = 0x04
        time = Long()
        day_time = Long()

    class EntityEquipment(ServerMessage):
        id = 0x05
        eid = Int()
        slot = Short()
        item = ItemStack()

    class SpawnPosition(ServerMessage):
        id = 0x06
        x = Int()
        y = Int()
        z = Int()

    class UseEntity(ClientMessage):
        id = 0x07
        eid = Int()
        target_eid = Int()
        left_click = Bool()

    class UpdateHealth(ServerMessage):
        id = 0x08
        health = Short()
        food = Short()
        food_saturation = Float()

    class Respawn(Message):
        id = 0x09
        world = Int()
        difficulty = Byte()
        mode = Byte()
        world_height = Short()
        level_type = String()

    class PlayerState(ClientMessage):
        id = 0x0a
        on_ground = Bool()

    class PlayerPosition(Message):
        id = 0x0b
        x = Double()
        y = Double()
        stance = Double()
        z = Double()
        on_ground = Bool()

    class PlayerLook(ClientMessage):
        id = 0x0c
        yaw = Float()
        pitch = Float()
        on_ground = Bool()

    class PlayerPositionAndLook(Message):
        id = 0x0d
        x = Double()
        y = Double()
        stance = Double()
        z = Double()
        yaw = Float()
        pitch = Float()
        on_ground = Bool()

    class Digging(Message):
        id = 0x0e
        status = Byte()
        x = Int()
        y = Byte()
        z = Int()
        face = Byte()

    class BlockPlacement(ClientMessage):
        id = 0x0f
        x = Int()
        y = Byte()
        z = Int()
        direction = Byte()
        item = ItemStack()
        block_x = Byte()
        block_y = Byte()
        block_z = Byte()

    class HeldItemSelection(Message):
        id = 0x10
        slot = Short()

    class UseBed(ServerMessage):
        id = 0x11
        eid = Int()
        in_bed = Bool()
        x = Int()
        y = Byte()
        z = Int()

    class ChangeAnimation(Message):
        id = 0x12
        eid = Int()
        animation = Byte()

    class EntityAction(Message):
        id = 0x13
        eid = Int()
        action = Byte()

    class EntitySpawn(ServerMessage):
        id = 0x14
        eid = Int()
        name = String()
        x = Int()
        y = Int()
        z = Int()
        rotation = Byte()
        pitch = Byte()
        curr_item = Short()

    class PickupSpawn(Message):
        id = 0x15
        eid = Int()
        item = ItemStack()
        x = Int()
        y = Int()
        z = Int()
        rotation = Byte()
        pitch = Byte()
        roll = Byte()

    class CollectItem(ServerMessage):
        id = 0x16
        item_eid = Int()
        collector_eid = Int()

    class SpawnObject(ServerMessage):
        id = 0x17
        eid = Int()
        type = Byte()
        x = Int()
        y = Int()
        z = Int()
        pitch = Byte()
        yaw = Byte()
        data = Int()
        speed_x = Conditional(Short(), lambda msg: msg.data > 0)
        speed_y = Conditional(Short(), lambda msg: msg.data > 0)
        speed_z = Conditional(Short(), lambda msg: msg.data > 0)

    class MobSpawn(ServerMessage):
        id = 0x18
        eid = Int()
        mob_type = Byte()
        x = Int()
        y = Int()
        z = Int()
        yaw = Byte()
        pitch = Byte()
        head_yaw = Byte()
        u1 = Short()
        u2 = Short()
        u3 = Short()
        metadata = Metadata()

    class Painting(ServerMessage):
        id = 0x19
        eid = Int()
        title = String()
        x = Int()
        y = Int()
        z = Int()
        type = Int()

    class ExperienceOrb(ServerMessage):
        id = 0x1a
        eid = Int()
        x = Int()
        y = Int()
        z = Int()
        count = Short()

    class EntityVelocity(Message):
        id = 0x1c
        eid = Int()
        x = Short()
        y = Short()
        z = Short()

    class DestroyEntity(ServerMessage):
        id = 0x1d
        eids = List(Int(), size=Byte())

    class Entity(ServerMessage):
        id = 0x1e
        eid = Int()

    class EntityRelativeMove(ServerMessage):
        id = 0x1f
        eid = Int()
        x = Byte()
        y = Byte()
        z = Byte()

    class EntityLook(ServerMessage):
        id = 0x20
        eid = Int()
        yaw = Byte()
        pitch = Byte()

    class EntityLookAndRelativeMove(ServerMessage):
        id = 0x21
        eid = Int()
        x = Byte()
        y = Byte()
        z = Byte()
        yaw = Byte()
        pitch = Byte()

    class EntityTeleport(ServerMessage):
        id = 0x22
        eid = Int()
        x = Int()
        y = Int()
        z = Int()
        yaw = Byte()
        pitch = Byte()

    class EntityHeadLook(ServerMessage):
        id = 0x23
        eid = Int()
        head_yaw = Byte()

    class EntityStatus(ServerMessage):
        id = 0x26
        eid = Int()
        status = Byte()

    class AttachEntity(Message):
        id = 0x27
        eid = Int()
        vehicle_id = Int()

    class EntityMetadata(Message):
        id = 0x28
        eid = Int()
        metadata = Metadata()

    class EntityEffect(Message):
        id = 0x29
        eid = Int()
        effect_id = Byte()
        amplifier = Byte()
        duration = Short()

    class RemoveEntityEffect(Message):
        id = 0x2a
        eid = Int()
        effect_id = Byte()

    class Experience(ServerMessage):
        id = 0x2b
        curr_exp = Float()
        level = Short()
        tot_exp = Short()

    class Chunk(ServerMessage):
        id = 0x33
        x = Int()
        z = Int()
        continuous = Bool()
        chunk_bitmap = Short()
        add_bitmap = Short()
        data = Data(Int())

    class MultiBlockChange(ServerMessage):
        id = 0x34
        chunk_x = Int()
        chunk_z = Int()
        block_count = Short()  # This does not get updated automatically
        changes = Data(Int())

    class BlockChange(ServerMessage):
        id = 0x35
        x = Int()
        y = Byte()
        z = Int()
        block_type = Short()
        block_metadata = Byte()

    class BlockAction(ServerMessage):
        id = 0x36
        x = Int()
        y = Short()
        z = Int()
        instrument_type = Byte()
        pitch = Byte()
        type = Short()

    class BlockMining(ServerMessage):
        id = 0x37
        eid = Int()
        x = Int()
        y = Int()
        z = Int()
        status = Byte()

    class ChunkBulk(ServerMessage):
        id = 0x38
        chunk_count = Short()
        data_length = Int()
        sky_light = Bool()
        data = Data("data_length")
        metadata = List(Object(
            x=Int(),
            z=Int(),
            chunk_bitmap=Short(),
            add_bitmap=Short()
        ), size="chunk_count")

    class Explosion(ServerMessage):
        id = 0x3c
        x = Double()
        y = Double()
        z = Double()
        radius = Float()
        records = List(Object(
            x=Byte(),
            y=Byte(),
            z=Byte()
        ), size=Int())
        push_x = Float()
        push_y = Float()
        push_z = Float()

    class SoundEffect(ServerMessage):
        id = 0x3d
        effect_id = Int()
        x = Int()
        y = Byte()
        z = Int()
        data = Int()
        constant_volume = Bool()

    class NamedSoundEffect(ServerMessage):
        id = 0x3e
        sound_name = String()
        x = Int()
        y = Int()
        z = Int()
        volume = Float()
        pitch = Byte()

    class ChangeGameState(Message):
        id = 0x46
        reason = Byte()
        game_mode = Byte()

    class SpawnGlobalEntity(ServerMessage):
        id = 0x47
        eid = Int()
        type = Byte()
        x = Int()
        y = Int()
        z = Int()

    class OpenWindow(ServerMessage):
        id = 0x64
        window_id = Byte()
        type = Byte()
        title = String()
        slot_count = Byte()
        custom_title = Bool()

    class CloseWindow(Message):
        id = 0x65
        window_id = Byte()

    class WindowClick(ClientMessage):
        id = 0x66
        window_id = Byte()
        slot = Short()
        right_click = Byte()
        action_id = Short()
        shift = Byte()
        details = ItemStack()

    class SetSlot(ServerMessage):
        id = 0x67
        window_id = Byte()
        slot = Short()
        item = ItemStack()

    class WindowItems(ServerMessage):
        id = 0x68
        window_id = Byte()
        items = List(ItemStack(), Short())

    class UpdateProgressBar(ServerMessage):
        id = 0x69
        window_id = Byte()
        progress_bar = Short()
        value = Short()

    class Transaction(Message):
        id = 0x6a
        window_id = Byte()
        action_id = Short()
        accepted = Bool()

    class CreativeInventoryAction(Message):
        id = 0x6b
        slot = Short()
        details = ItemStack()

    class EnchantItem(ClientMessage):
        id = 0x6c
        window_id = Byte()
        enchantment = Byte()

    class UpdateSign(Message):
        id = 0x82
        x = Int()
        y = Short()
        z = Int()
        text1 = String()
        text2 = String()
        text3 = String()
        text4 = String()

    class ItemData(Message):
        id = 0x83
        item_type = Short()
        item_id = Short()
        data = Data(Short())

    class UpdateTileEntity(ServerMessage):
        id = 0x84
        x = Int()
        y = Short()
        z = Int()
        action = Byte()
        data = Data(Short())

    class IncrementStatistic(ServerMessage):
        id = 0xc8
        stat_id = Int()
        amount = Byte()

    class PlayerListItem(ServerMessage):
        id = 0xc9
        name = String()
        online = Bool()
        ping = Short()

    class Abilities(Message):
        id = 0xca
        abilities = Byte()
        flying_speed = Byte()
        walking_speed = Byte()

    class TabCompletion(Message):
        id = 0xcb
        text = String()

    class Settings(ClientMessage):
        id = 0xcc
        locale = String()
        view_distance = Byte()
        chat_flags = Byte()
        difficulty = Byte()
        show_cape = Bool()

    class ClientStatus(Message):
        id = 0xcd
        payload = Byte()

    class CreateScoreboard(ServerMessage):
        id = 0xce
        name = String()
        display_text = String()
        remove = Byte()

    class UpdateScore(ServerMessage):
        id = 0xcf
        item_name = String()
        remove = Byte()
        score_name = String()
        value = Int()

    class DisplayScoreboard(ServerMessage):
        id = 0xd0
        position = Byte()
        score_name = String()

    class Teams(ServerMessage):
        id = 0xd1
        name = String()
        mode = Byte()
        display_name = Conditional(String(), lambda msg: msg.mode in (0, 2))
        prefix = Conditional(String(), lambda msg: msg.mode in (0, 2))
        suffix = Conditional(String(), lambda msg: msg.mode in (0, 2))
        friendly_fire = Conditional(Bool(), lambda msg: msg.mode in (0, 2))
        players = Conditional(List(String(), size=Short()),
                              lambda msg: msg.mode in (0, 3, 4))

    class EncryptionKeyResponse(Message):
        id = 0xfc
        shared_secret = Data(Short())
        challenge_token = Data(Short())

    class EncryptionKeyRequest(ServerMessage):
        id = 0xfd
        server_id = String()
        public_key = Data(Short())
        challenge_token = Data(Short())


### VERSION 72 - Corresponds to 1.6
with protocol.version(72):
    class UpdateHealth(ServerMessage):
        id = 0x08
        health = Float()
        food = Short()
        food_saturation = Float()

    class EntityAction(Message):
        id = 0x13
        eid = Int()
        action = Byte()
        unknown = Int()

    class SteerVehicle(Message):
        id = 0x1b
        sideways = Float()
        forward = Float()
        jump = Bool()
        unmount = Bool()

    class AttachEntity(Message):
        id = 0x27
        eid = Int()
        vehicle_id = Int()
        leash = Bool()

    class EntityProperties(ServerMessage):
        id = 0x2c
        eid = Int()
        properties = Dict(String(), Double(), size=Int())

    class OpenWindow(ServerMessage):
        id = 0x64
        window_id = Byte()
        type = Byte()
        title = String()
        slot_count = Byte()
        custom_title = Byte()
        eid = Conditional(Int(), lambda msg: msg.type == 11)

    class IncrementStatistic(ServerMessage):
        id = 0xc8
        stat_id = Int()
        amount = Int()

    class Abilities(Message):
        id = 0xca
        abilities = Byte()
        flying_speed = Float()
        walking_speed = Float()


### VERSION 74 - Corresponds to 1.6.2
with protocol.version(74):
    class EntityProperties(ServerMessage):
        id = 0x2c
        eid = Int()
        properties = Dict(String(), Object(
            value=Double(),
            list=List(Object(
                most_significant=Long(),
                least_significant=Long(),
                amount=Double(),
                operation=Byte()
            ), size=Short())
        ), size=Int())

    class OpenTileEditor(ServerMessage):
        id = 0x85
        unknown = Byte()
        x = Int()
        y = Int()
        z = Int()


### VERSION 75 - Corresponds to 13w36a
with protocol.version(75):
    class NamedSoundEffect(ServerMessage):
        id = 0x3e
        sound_name = String()
        x = Int()
        y = Int()
        z = Int()
        volume = Float()
        pitch = Byte()
        unknown = Byte()

    class IncrementStatistic(ServerMessage):
        id = 0xc8
        stats = Dict(String(), Int(),  size=Int())
