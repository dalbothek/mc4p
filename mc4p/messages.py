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

from parsing import (defhandshakemsg, defmsg, MC_bool, MC_byte, MC_chunk,
                     MC_chunk2, MC_double, MC_entity_list, MC_fireball_data,
                     MC_explosion_records, MC_float, MC_int, MC_inventory,
                     MC_inventory2, MC_inventory3, MC_item_data, MC_long,
                     MC_metadata, MC_multi_block_change, MC_slot_update,
                     MC_multi_block_change2, MC_short, MC_slot_update2,
                     MC_slot_update3, MC_string, MC_string8, MC_unsigned_byte,
                     MC_blob, MC_chunks, MC_chunks2, MC_tile_entity,
                     MC_item_data2, MC_metadata2, defconditionalmsg,
                     MC_player_list, MC_entity_properties)

protocol = {}

### GENERIC MESSAGES - Independent of protocol version ###

protocol[0] = [None] * 256, [None] * 256
cli_msgs, srv_msgs = protocol[0]

cli_msgs[0x01] = defmsg(0x01, "Magic constant", [])

cli_msgs[0x02] = defhandshakemsg([
    ('username',MC_string),
    ('host',MC_string),
    ('port',MC_int)])

cli_msgs[0xfa] = \
srv_msgs[0xfa] = defmsg(0xfa, "Plugin message", [
    ('channel', MC_string),
    ('data', MC_string8)])

cli_msgs[0xfe] = defmsg(0xfe, "Server List Ping", [])

cli_msgs[0xff] = \
srv_msgs[0xff] = defmsg(0xff, "Disconnect/Kick", [
    ('reason', MC_string)])

### VERSION 32 - Corresponds to 12w18a

protocol[32] = tuple(map(list, protocol[0]))
cli_msgs, srv_msgs = protocol[32]

cli_msgs[0x00] = \
srv_msgs[0x00] = defmsg(0x00,"Keep Alive",[
    ('id', MC_int)])

cli_msgs[0x01] = defmsg(0x01, "Login packet", [])

srv_msgs[0x01] = defmsg(0x01, "Login packet", [
    ('eid', MC_int),
    ('level_type', MC_string),
    ('server_mode', MC_byte),
    ('dimension', MC_byte),
    ('difficulty', MC_byte),
    ('unused', MC_unsigned_byte),
    ('max_players', MC_unsigned_byte)])

cli_msgs[0x03] = \
srv_msgs[0x03] = defmsg(0x03, "Chat",[
    ('chat_msg',MC_string)])

srv_msgs[0x04] = defmsg(0x04, "Time", [
    ('time',MC_long)])

cli_msgs[0x05] = \
srv_msgs[0x05] = defmsg(0x05, "Entity Equipment Spawn",[
    ('eid',MC_int),
    ('slot',MC_short),
    ('item_id',MC_short),
    ('unknown',MC_short)])

srv_msgs[0x06] = defmsg(0x06, "Spawn position",[
    ('x',MC_int),
    ('y',MC_int),
    ('z',MC_int)])

cli_msgs[0x07] = defmsg(0x07, "Use entity", [
    ('eid',MC_int),
    ('target_eid',MC_int),
    ('left_click',MC_bool)])

srv_msgs[0x08] = defmsg(0x08, "Update health", [
    ('health',MC_short),
    ('food', MC_short),
    ('food_saturation', MC_float)])

cli_msgs[0x09] = defmsg(0x09, "Respawn", [])
srv_msgs[0x09] = defmsg(0x09, "Respawn", [
    ('world', MC_int),
    ('difficulty', MC_byte),
    ('mode', MC_byte),
    ('world_height', MC_short),
    ('level_type', MC_string)])

cli_msgs[0x0a] = defmsg(0x0a, "Player state", [
    ('on_ground',MC_bool)])

cli_msgs[0x0b] = \
srv_msgs[0x0b] = defmsg(0x0b, "Player position", [
    ('x',MC_double),
    ('y',MC_double),
    ('stance',MC_double),
    ('z',MC_double),
    ('on_ground',MC_bool)])

cli_msgs[0x0c] = defmsg(0x0c, "Player look", [
    ('yaw',MC_float),
    ('pitch',MC_float),
    ('on_ground',MC_bool)])

# Note the difference in ordering of 'stance'!
cli_msgs[0x0d] = defmsg(0x0d, "Player position and look",[
    ('x',MC_double),
    ('y',MC_double),
    ('stance',MC_double),
    ('z',MC_double),
    ('yaw',MC_float),
    ('pitch',MC_float),
    ('on_ground',MC_bool)])
srv_msgs[0x0d] = defmsg(0x0d, "Player position and look", [
    ('x',MC_double),
    ('stance',MC_double),
    ('y',MC_double),
    ('z',MC_double),
    ('yaw',MC_float),
    ('pitch',MC_float),
    ('on_ground',MC_bool)])

cli_msgs[0x0e] = \
srv_msgs[0x0e] = defmsg(0x0e, "Digging", [
    ('status',MC_byte),
    ('x',MC_int),
    ('y',MC_byte),
    ('z',MC_int),
    ('face',MC_byte)])

cli_msgs[0x0f] = \
srv_msgs[0x0f] = defmsg(0x0f, "Block placement", [
    ('x',MC_int),
    ('y',MC_byte),
    ('z',MC_int),
    ('dir',MC_byte),
    ('details',MC_slot_update2)])

cli_msgs[0x10] = \
srv_msgs[0x10] = defmsg(0x10, "Held item selection",[
    ('slot_id', MC_short)])

srv_msgs[0x11] = defmsg(0x11, "Use bed", [
    ('eid', MC_int),
    ('in_bed', MC_bool),
    ('x', MC_int),
    ('y', MC_byte),
    ('z', MC_int)])

cli_msgs[0x12] = \
srv_msgs[0x12] = defmsg(0x12, "Change animation",[
    ('eid',MC_int),
    ('animation',MC_byte)])

cli_msgs[0x13] = \
srv_msgs[0x13] = defmsg(0x13, "Entity action", [
    ('eid',MC_int),
    ('action', MC_byte)])

srv_msgs[0x14] = defmsg(0x14, "Entity spawn", [
    ('eid', MC_int),
    ('name', MC_string),
    ('x', MC_int),
    ('y', MC_int),
    ('z', MC_int),
    ('rotation', MC_byte),
    ('pitch', MC_byte),
    ('curr_item', MC_short)])

cli_msgs[0x15] = \
srv_msgs[0x15] = defmsg(0x15, "Pickup spawn", [
    ('eid',MC_int),
    ('item',MC_short),
    ('count',MC_byte),
    ('data',MC_short),
    ('x',MC_int),
    ('y',MC_int),
    ('z',MC_int),
    ('rotation',MC_byte),
    ('pitch',MC_byte),
    ('roll',MC_byte)])

srv_msgs[0x16] = defmsg(0x16, "Collect item", [
    ('item_eid',MC_int),
    ('collector_eid',MC_int)])

srv_msgs[0x17] = defmsg(0x17, "Add vehicle/object", [
    ('eid',MC_int),
    ('type',MC_byte),
    ('x',MC_int),
    ('y',MC_int),
    ('z',MC_int),
    ('fireball_data',MC_fireball_data)])

srv_msgs[0x18] = defmsg(0x18, "Mob spawn", [
    ('eid',MC_int),
    ('mob_type',MC_byte),
    ('x',MC_int),
    ('y',MC_int),
    ('z',MC_int),
    ('yaw',MC_byte),
    ('pitch',MC_byte),
    ('head_yaw',MC_byte),
    ('metadata',MC_metadata)])

srv_msgs[0x19] = defmsg(0x19, "Painting", [
    ('eid', MC_int),
    ('title', MC_string),
    ('x', MC_int),
    ('y', MC_int),
    ('z', MC_int),
    ('type', MC_int)])

srv_msgs[0x1a] = defmsg(0x1a, "Experience orb", [
    ('eid', MC_int),
    ('x', MC_int),
    ('y', MC_int),
    ('z', MC_int),
    ('count', MC_short)])

cli_msgs[0x1c] = \
srv_msgs[0x1c] = defmsg(0x1c, "Entity velocity", [
    ('eid',MC_int),
    ('vel_x',MC_short),
    ('vel_y',MC_short),
    ('vel_z',MC_short)])

srv_msgs[0x1d] = defmsg(0x1d, "Destroy entity", [
    ('eid',MC_int)])

srv_msgs[0x1e] = defmsg(0x1e, "Entity", [
    ('eid', MC_int)])

srv_msgs[0x1f] = defmsg(0x1f, "Entity relative move", [
    ('eid',MC_int),
    ('dx',MC_byte),
    ('dy',MC_byte),
    ('dz',MC_byte)])

srv_msgs[0x20] = defmsg(0x20, "Entity look", [
    ('eid', MC_int),
    ('yaw', MC_byte),
    ('pitch', MC_byte)])

srv_msgs[0x21] = defmsg(0x21, "Entity look/relative move", [
    ('eid',MC_int),
    ('dx',MC_byte),
    ('dy',MC_byte),
    ('dz',MC_byte),
    ('yaw',MC_byte),
    ('pitch',MC_byte)])

srv_msgs[0x22] = defmsg(0x22, "Entity teleport", [
    ('eid', MC_int),
    ('x', MC_int),
    ('y', MC_int),
    ('z', MC_int),
    ('yaw', MC_byte),
    ('pitch', MC_byte)])

srv_msgs[0x23] = defmsg(0x23, "Entity head look", [
    ('eid',MC_int),
    ('head_yaw',MC_byte)])

srv_msgs[0x26] = defmsg(0x26, "Entity status", [
    ('eid',MC_int),
    ('status',MC_byte)])

cli_msgs[0x27] = \
srv_msgs[0x27] = defmsg(0x27, "Attach entity", [
    ('eid',MC_int),
    ('vehicle_id',MC_int)])

cli_msgs[0x28] = \
srv_msgs[0x28] = defmsg(0x28, "Entity metadata", [
    ('eid',MC_int),
    ('metadata',MC_metadata)])

cli_msgs[0x29] = \
srv_msgs[0x29] = defmsg(0x29, "Entity Effect", [
    ('eid', MC_int),
    ('effect_id', MC_byte),
    ('amplifier', MC_byte),
    ('duration', MC_short)])

cli_msgs[0x2a] = \
srv_msgs[0x2a] = defmsg(0x2a, "Remove entity effect", [
    ('eid', MC_int),
    ('effect_id', MC_byte)])

srv_msgs[0x2b] = defmsg(0x2b, "Experience", [
    ('curr_exp', MC_float),
    ('level', MC_short),
    ('tot_exp', MC_short)])

srv_msgs[0x32] = defmsg(0x32, "Pre-chunk", [
    ('x',MC_int),
    ('z',MC_int),
    ('mode',MC_bool)])

srv_msgs[0x33] = defmsg(0x33, "Chunk", [
    ('x',MC_int),
    ('z',MC_int),
    ('continuous',MC_bool),
    ('chunk_bitmap',MC_short),
    ('add_bitmap',MC_short),
    ('chunk',MC_chunk2)])

srv_msgs[0x34] = defmsg(0x34, "Multi-block change", [
    ('chunk_x',MC_int),
    ('chunk_z',MC_int),
    ('block_count',MC_short),
    ('changes',MC_multi_block_change2)])

cli_msgs[0x35] = \
srv_msgs[0x35] = defmsg(0x35, "Block change", [
    ('x',MC_int),
    ('y',MC_byte),
    ('z',MC_int),
    ('block_type',MC_byte),
    ('block_metadata',MC_byte)])

srv_msgs[0x36] = defmsg(0x36, "Play note block",[
    ('x', MC_int),
    ('y', MC_short),
    ('z', MC_int),
    ('instrument_type', MC_byte),
    ('pitch', MC_byte)])

srv_msgs[0x3c] = defmsg(0x3c, "Explosion", [
    ('x', MC_double),
    ('y', MC_double),
    ('z', MC_double),
    ('unknown', MC_float),
    ('records', MC_explosion_records)])

srv_msgs[0x3d] = defmsg(0x3d, "Sound effect", [
    ('effect_id', MC_int),
    ('x', MC_int),
    ('y', MC_byte),
    ('z', MC_int),
    ('data', MC_int)])

srv_msgs[0x3e] = defmsg(0x3e, "Named Sound Effect", [
    ('sound_name', MC_string),
    ('x', MC_int),
    ('y', MC_int),
    ('z', MC_int),
    ('volume', MC_byte),
    ('pitch', MC_byte)])

cli_msgs[0x46] = \
srv_msgs[0x46] = defmsg(0x46, "New/Invalid State", [
    ('reason', MC_byte),
    ('game_mode', MC_byte)])

srv_msgs[0x47] = defmsg(0x47, "Weather", [
    ('eid', MC_int),
    ('raining', MC_bool),
    ('x', MC_int),
    ('y', MC_int),
    ('z', MC_int)])

srv_msgs[0x64] = defmsg(0x64, "Open window", [
    ('window_id', MC_byte),
    ('inv_type', MC_byte),
    ('window_title', MC_string),
    ('num_slots', MC_byte)])

cli_msgs[0x65] = \
srv_msgs[0x65] = defmsg(0x65, "Close window", [
    ('window_id', MC_byte)])

cli_msgs[0x66] = defmsg(0x66, "Window click", [
    ('window_id', MC_byte),
    ('slot', MC_short),
    ('is_right_click', MC_bool),
    ('action_num', MC_short),
    ('shift', MC_bool),
    ('details', MC_slot_update2)])

srv_msgs[0x67] = defmsg(0x67, "Set slot", [
    ('window_id',MC_byte),
    ('slot',MC_short),
    ('slot_update',MC_slot_update2)])

srv_msgs[0x68] = defmsg(0x68, "Window items", [
    ('window_id',MC_byte),
    ('inventory',MC_inventory2)])

srv_msgs[0x69] = defmsg(0x69, "Update progress bar", [
    ('window_id', MC_byte),
    ('progress_bar',MC_short),
    ('value',MC_short)])

cli_msgs[0x6a] = \
srv_msgs[0x6a] = defmsg(0x6a, "Transaction", [
    ('window_id', MC_byte),
    ('action_num', MC_short),
    ('accepted', MC_bool)])

cli_msgs[0x6b] = \
srv_msgs[0x6b] = defmsg(0x6b, "Creative inventory action", [
    ('slot', MC_short),
    ('details', MC_slot_update2)])

cli_msgs[0x6c] = defmsg(0x6c, "Enchant Item", [
    ('window_id', MC_byte),
    ('enchantment', MC_byte)])

cli_msgs[0x82] = \
srv_msgs[0x82] = defmsg(0x82, "Update sign", [
    ('x', MC_int),
    ('y', MC_short),
    ('z', MC_int),
    ('text1', MC_string),
    ('text2', MC_string),
    ('text3', MC_string),
    ('text4', MC_string)])

cli_msgs[0x83] = \
srv_msgs[0x83] = defmsg(0x83, "Item data", [
    ('item_type', MC_short),
    ('item_id', MC_short),
    ('data', MC_item_data)])

srv_msgs[0x84] = defmsg(0x84, "Update tile entity", [
    ('x',MC_int),
    ('y',MC_short),
    ('z',MC_int),
    ('action',MC_byte),
    ('custom1',MC_int),
    ('custom2',MC_int),
    ('custom3',MC_int)])

srv_msgs[0xc8] = defmsg(0xc8, "Increment statistic", [
    ('stat_id', MC_int),
    ('amount', MC_byte)])

srv_msgs[0xc9] = defmsg(0xc9, "Player list item", [
    ('name', MC_string),
    ('online', MC_bool),
    ('ping', MC_short)])

cli_msgs[0xca] = \
srv_msgs[0xca] = defmsg(0xca, "Abilities", [
    ('abilities', MC_byte),
    ('flying_speed', MC_byte),
    ('walking_speed', MC_byte)])

cli_msgs[0xcb] = \
srv_msgs[0xcb] = defmsg(0xcb, "Tab completion", [
    ('text', MC_string)])

cli_msgs[0xcc] = defmsg(0xcc, "Settings", [
    ('locale', MC_string),
    ('view_distance', MC_byte),
    ('chat_flags', MC_byte),
    ('unknown', MC_byte)])

cli_msgs[0xfc] = \
srv_msgs[0xfc] = defmsg(0xfc, "Encryption Key Response", [
    ('shared_secret', MC_blob)])

srv_msgs[0xfd] = defmsg(0xfd, "Encryption Key Request", [
    ('server_id', MC_string),
    ('public_key', MC_blob)])


### VERSION 33 - Corresponds to 12w21a

protocol[33] = tuple(map(list, protocol[32]))


### VERSION 34 - Corresponds to 12w22a

protocol[34] = tuple(map(list, protocol[33]))
cli_msgs, srv_msgs = protocol[34]

cli_msgs[0x0f] = defmsg(0x0f, "Block placement", [
    ('x',MC_int),
    ('y',MC_byte),
    ('z',MC_int),
    ('dir',MC_byte),
    ('details',MC_slot_update2),
    ('block_x', MC_byte),
    ('block_y', MC_byte),
    ('block_z', MC_byte)])


### VERSION 35 - Corresponds to 12w23a

protocol[35] = tuple(map(list, protocol[34]))
cli_msgs, srv_msgs = protocol[35]

srv_msgs[0x05] = defmsg(0x05, "Entity Equipment",[
    ('eid',MC_int),
    ('slot',MC_short),
    ('item',MC_slot_update2)])

srv_msgs[0x37] = defmsg(0x37, "Block Mining",[
    ('eid',MC_int),
    ('x',MC_int),
    ('y',MC_int),
    ('z',MC_int),
    ('status',MC_byte)])


### VERSION 36 - Corresponds to 12w24a

protocol[36] = tuple(map(list, protocol[35]))
cli_msgs, srv_msgs = protocol[36]

srv_msgs[0x05] = defmsg(0x05, "Entity Equipment",[
    ('eid',MC_int),
    ('slot',MC_short),
    ('item',MC_slot_update3)])

cli_msgs[0x0f] = defmsg(0x0f, "Block placement", [
    ('x',MC_int),
    ('y',MC_byte),
    ('z',MC_int),
    ('dir',MC_byte),
    ('details',MC_slot_update3),
    ('block_x', MC_byte),
    ('block_y', MC_byte),
    ('block_z', MC_byte)])

srv_msgs[0x3c] = defmsg(0x3c, "Explosion", [
    ('x', MC_double),
    ('y', MC_double),
    ('z', MC_double),
    ('unknown', MC_float),
    ('records', MC_explosion_records),
    ('unknown1', MC_float),
    ('unknown2', MC_float),
    ('unknown3', MC_float)])

cli_msgs[0x66] = defmsg(0x66, "Window click", [
    ('window_id', MC_byte),
    ('slot', MC_short),
    ('is_right_click', MC_bool),
    ('action_num', MC_short),
    ('shift', MC_bool),
    ('details', MC_slot_update3)])

srv_msgs[0x67] = defmsg(0x67, "Set slot", [
    ('window_id',MC_byte),
    ('slot',MC_short),
    ('slot_update',MC_slot_update3)])

srv_msgs[0x68] = defmsg(0x68, "Window items", [
    ('window_id',MC_byte),
    ('inventory',MC_inventory3)])

cli_msgs[0x6b] = \
srv_msgs[0x6b] = defmsg(0x6b, "Creative inventory action", [
    ('slot', MC_short),
    ('details', MC_slot_update3)])

cli_msgs[0xcd] = \
srv_msgs[0xcd] = defmsg(0xcd, "Respawn", [
    ('payload', MC_byte)])


### VERSION 37 - Corresponds to 12w25a

protocol[37] = tuple(map(list, protocol[36]))
cli_msgs, srv_msgs = protocol[37]

srv_msgs[0x3e] = defmsg(0x3e, "Named Sound Effect", [
    ('sound_name', MC_string),
    ('x', MC_int),
    ('y', MC_int),
    ('z', MC_int),
    ('volume', MC_float),
    ('pitch', MC_byte)])

cli_msgs[0xfc] = \
srv_msgs[0xfc] = defmsg(0xfc, "Encryption Key Response", [
    ('shared_secret', MC_blob),
    ('challenge_token', MC_blob)])

srv_msgs[0xfd] = defmsg(0xfd, "Encryption Key Request", [
    ('server_id', MC_string),
    ('public_key', MC_blob),
    ('challenge_token', MC_blob)])


### VERSION 38 - Corresponds to 12w27a

protocol[38] = tuple(map(list, protocol[37]))
cli_msgs, srv_msgs = protocol[38]

srv_msgs[0x18] = defmsg(0x18, "Mob spawn", [
    ('eid',MC_int),
    ('mob_type',MC_byte),
    ('x',MC_int),
    ('y',MC_int),
    ('z',MC_int),
    ('yaw',MC_byte),
    ('pitch',MC_byte),
    ('head_yaw',MC_byte),
    ('u1',MC_short),
    ('u2',MC_short),
    ('u3',MC_short),
    ('metadata',MC_metadata)])

srv_msgs[0x1d] = defmsg(0x1d, "Destroy entity", [
    ('entities',MC_entity_list)])

srv_msgs[0x33] = defmsg(0x33, "Chunk", [
    ('x',MC_int),
    ('z',MC_int),
    ('continuous',MC_bool),
    ('chunk_bitmap',MC_short),
    ('add_bitmap',MC_short),
    ('chunk',MC_chunk)])

srv_msgs[0x36] = defmsg(0x36, "Block Action",[
    ('x', MC_int),
    ('y', MC_short),
    ('z', MC_int),
    ('instrument_type', MC_byte),
    ('pitch', MC_byte),
    ('type', MC_short)])

srv_msgs[0x38] = defmsg(0x38, "Chunk Bulk",[
    ('chunks', MC_chunks)])

srv_msgs[0x14] = defmsg(0x14, "Entity spawn", [
    ('eid', MC_int),
    ('name', MC_string),
    ('x', MC_int),
    ('y', MC_int),
    ('z', MC_int),
    ('rotation', MC_byte),
    ('pitch', MC_byte),
    ('curr_item', MC_short),
    ('metadata',MC_metadata)])

srv_msgs[0x35] = defmsg(0x35, "Block change", [
    ('x',MC_int),
    ('y',MC_byte),
    ('z',MC_int),
    ('block_type',MC_short),
    ('block_metadata',MC_byte)])


### VERSION 39 - Corresponds to 12w30c

protocol[39] = tuple(map(list, protocol[38]))
cli_msgs, srv_msgs = protocol[39]

srv_msgs[0x84] = defmsg(0x84, "Update tile entity", [
    ('x',MC_int),
    ('y',MC_short),
    ('z',MC_int),
    ('action',MC_byte),
    ('data',MC_tile_entity)])


### VERSION 40 - Corresponds to 12w32a

protocol[40] = tuple(map(list, protocol[39]))
cli_msgs, srv_msgs = protocol[40]

srv_msgs[0x04] = defmsg(0x04, "Time", [
    ('time',MC_long),
    ('day_time',MC_long)])


### VERSION 41 - Corresponds to 12w34a

protocol[41] = tuple(map(list, protocol[40]))


### VERSION 42 - Corresponds to 12w36a

protocol[42] = tuple(map(list, protocol[41]))
cli_msgs, srv_msgs = protocol[42]

cli_msgs[0x15] = \
srv_msgs[0x15] = defmsg(0x15, "Pickup spawn", [
    ('eid',MC_int),
    ('item',MC_slot_update3),
    ('x',MC_int),
    ('y',MC_int),
    ('z',MC_int),
    ('rotation',MC_byte),
    ('pitch',MC_byte),
    ('roll',MC_byte)])


### VERSION 43 - Corresponds to 12w38a

protocol[43] = tuple(map(list, protocol[42]))


### VERSION 44 - Corresponds to 12w40a

protocol[44] = tuple(map(list, protocol[43]))
cli_msgs, srv_msgs = protocol[44]

cli_msgs[0x66] = defmsg(0x66, "Window click", [
    ('window_id', MC_byte),
    ('slot', MC_short),
    ('is_right_click', MC_byte),
    ('action_num', MC_short),
    ('shift', MC_byte),
    ('details', MC_slot_update3)])


### VERSION 46 - Corresponds to 12w41a

protocol[46] = tuple(map(list, protocol[44]))
cli_msgs, srv_msgs = protocol[46]

cli_msgs[0xcc] = defmsg(0xcc, "Settings", [
    ('locale', MC_string),
    ('view_distance', MC_byte),
    ('chat_flags', MC_byte),
    ('difficulty', MC_byte),
    ('show_cape', MC_bool)])


### VERSION 47 - Corresponds to 12w42b

protocol[47] = tuple(map(list, protocol[46]))
cli_msgs, srv_msgs = protocol[47]

srv_msgs[0x3d] = defmsg(0x3d, "Sound effect", [
    ('effect_id', MC_int),
    ('x', MC_int),
    ('y', MC_byte),
    ('z', MC_int),
    ('data', MC_int),
    ('constant_volume', MC_bool)])


## Forge support
cli_msgs[0x01] = srv_msgs[0x01]


### VERSION 48 - Corresponds to 1.4.3

protocol[48] = tuple(map(list, protocol[47]))
cli_msgs, srv_msgs = protocol[48]

srv_msgs[0x14] = defmsg(0x14, "Entity spawn", [
    ('eid', MC_int),
    ('name', MC_string),
    ('x', MC_int),
    ('y', MC_int),
    ('z', MC_int),
    ('rotation', MC_byte),
    ('pitch', MC_byte),
    ('curr_item', MC_short),
    ('metadata',MC_metadata2)])

srv_msgs[0x18] = defmsg(0x18, "Mob spawn", [
    ('eid',MC_int),
    ('mob_type',MC_byte),
    ('x',MC_int),
    ('y',MC_int),
    ('z',MC_int),
    ('yaw',MC_byte),
    ('pitch',MC_byte),
    ('head_yaw',MC_byte),
    ('u1',MC_short),
    ('u2',MC_short),
    ('u3',MC_short),
    ('metadata',MC_metadata2)])

cli_msgs[0x28] = \
srv_msgs[0x28] = defmsg(0x28, "Entity metadata", [
    ('eid',MC_int),
    ('metadata',MC_metadata2)])


### VERSION 49 - Corresponds to 1.4.4

protocol[49] = tuple(map(list, protocol[48]))
cli_msgs, srv_msgs = protocol[49]

cli_msgs[0x83] = \
srv_msgs[0x83] = defmsg(0x83, "Item data", [
    ('item_type', MC_short),
    ('item_id', MC_short),
    ('data', MC_item_data2)])


### VERSION 50 - Corresponds to 12w49a

protocol[50] = tuple(map(list, protocol[49]))
cli_msgs, srv_msgs = protocol[50]

srv_msgs[0x17] = defmsg(0x17, "Add vehicle/object", [
    ('eid',MC_int),
    ('type',MC_byte),
    ('x',MC_int),
    ('y',MC_int),
    ('z',MC_int),
    ('yaw',MC_byte),
    ('pitch',MC_byte),
    ('fireball_data',MC_fireball_data)])


### VERSION 51 - Corresponds to 1.4.6

protocol[51] = tuple(map(list, protocol[50]))
cli_msgs, srv_msgs = protocol[51]

# 0x15 (Spawn Dropped Item) removed
cli_msgs[0x15] = \
srv_msgs[0x15] = None

srv_msgs[0x38] = defmsg(0x38, "Chunk Bulk",[
    ('chunks', MC_chunks2)])


### VERSION 52 - Corresponds to 13w01b
protocol[52] = tuple(map(list, protocol[51]))
cli_msgs, srv_msgs = protocol[52]

srv_msgs[0x64] = defmsg(0x64, "Open window", [
    ('window_id', MC_byte),
    ('inv_type', MC_byte),
    ('window_title', MC_string),
    ('num_slots', MC_byte),
    ('custom_title', MC_byte)])


### VERSION 53 - Corresponds to 13w02a
protocol[53] = protocol[52]


### VERSION 54 - Corresponds to 13w03a
protocol[54] = protocol[53]


### VERSION 55 - Corresponds to 13w04a
protocol[55] = tuple(map(list, protocol[54]))
cli_msgs, srv_msgs = protocol[55]

srv_msgs[0xce] = defmsg(0xce, "Create Scoreboard", [
    ('name', MC_string),
    ('display_text', MC_string),
    ('remove', MC_byte)])

srv_msgs[0xcf] = defmsg(0xcf, "Update Score", [
    ('item_name', MC_string),
    ('remove', MC_byte),
    ('score_name', MC_string),
    ('value', MC_int)])

srv_msgs[0xd0] = defmsg(0xd0, "Display Scoreboard", [
    ('position', MC_byte),
    ('score_name', MC_string)])


### VERSION 56 - Corresponds to 13w05a
protocol[56] = tuple(map(list, protocol[55]))
cli_msgs, srv_msgs = protocol[56]

srv_msgs[0xd1] = defconditionalmsg(0xd1, "Teams", [
    ('name', MC_string),
    ('mode', MC_byte),
    ('display_name', MC_string, lambda msg: msg['mode'] in (0, 2)),
    ('prefix', MC_string, lambda msg: msg['mode'] in (0, 2)),
    ('suffix', MC_string, lambda msg: msg['mode'] in (0, 2)),
    ('friendly_fire', MC_bool, lambda msg: msg['mode'] in (0, 2)),
    ('players', MC_player_list, lambda msg: msg['mode'] in (0, 3, 4))])


### VERSION 57-60 - Corresponds to 13w05a - 13w09c
protocol[60] = protocol[59] = protocol[58] = protocol[57] = protocol[56]


### VERSION 61 - Corresponds to 1.5.2
protocol[61] = protocol[60]


### VERSION 72 - Corresponds to 1.6
protocol[72] = protocol[61]
cli_msgs, srv_msgs = protocol[72]

srv_msgs[0x08] = defmsg(0x08, "Update health", [
    ('health', MC_float),
    ('food', MC_short),
    ('food_saturation', MC_float)])

cli_msgs[0x13] = \
srv_msgs[0x13] = defmsg(0x13, "Entity action", [
    ('eid', MC_int),
    ('action', MC_byte),
    ('un', MC_int)])

cli_msgs[0x1b]  = defmsg(0x1b, "Steer vehicle", [
    ('sideways', MC_float),
    ('forward', MC_float),
    ('jump', MC_bool),
    ('unmount', MC_bool)])

cli_msgs[0x27] = \
srv_msgs[0x27] = defmsg(0x27, "Attach entity", [
    ('eid', MC_int),
    ('vehicle_id', MC_int),
    ('leash', MC_bool)])

srv_msgs[0x2c] = defmsg(0x2c, "Entity Properties", [
    ('eid', MC_int),
    ('properties', MC_entity_properties)])

srv_msgs[0x64] = defconditionalmsg(0x64, "Open window", [
    ('window_id', MC_byte),
    ('inv_type', MC_byte),
    ('window_title', MC_string),
    ('num_slots', MC_byte),
    ('custom_title', MC_byte),
    ('un', MC_int, lambda msg: msg['inv_type'] == 11)])

srv_msgs[0xc8] = defmsg(0xc8, "Increment statistic", [
    ('stat_id', MC_int),
    ('amount', MC_int)])

cli_msgs[0xca] = \
srv_msgs[0xca] = defmsg(0xca, "Abilities", [
    ('abilities', MC_byte),
    ('flying_speed', MC_float),
    ('walking_speed', MC_float)])


### VERSION 73 - Corresponds to 1.6.1
protocol[73] = protocol[72]
