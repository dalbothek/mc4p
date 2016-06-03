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
import sys

import gevent.pool

from mc4p import authentication
from mc4p import network
from mc4p import util
from mc4p.tools import status


logger = logging.getLogger("info")


_AUTHENTICATOR = None


def get_server_info(server, authenticator=None, raise_errors=False,
                    logfile=None):
    if not isinstance(server, ServerInfo):
        if len(server) == 3:
            server = ServerInfo(server[0:2], id_=server[2], logfile=logfile)
        else:
            server = ServerInfo(server, logfile=logfile)

    try:
        _get_server_info(server, authenticator=authenticator)
    except Exception as e:
        server.error = str(e)
        if raise_errors:
            raise
        logger.error("Could not connect to %s: %s" % (repr(server).encode('punycode'), str(e).encode('punycode')))

    return server


def parse_packet_messages(packets, invalid_responses):
    message = None
    if packets:
        message = " ".join(
            util.parse_chat(packet.message) for packet in packets
        )

        for invalid_response in invalid_responses:
            if invalid_response in message.lower():
                message = None
    return(message)


def _get_server_info(server, authenticator=None):
    """
    Gathers additional info about a server by joining the game.
    """
    status.server_status(server, raise_errors=True)

    server.state = "connect"
    client = network.Client(server.addr, version=server.protocol_version,
                            logfile=server.logfile)

    @client.packet_handler(client.input_protocol.play.PluginMessage)
    def handle_plugin_message(packet):
        if packet.channel == "MC|Brand":
            server.brand = packet.parse_as_string()

    @client.packet_handler(client.input_protocol.play.JoinGame)
    def handle_join_game(packet):
        server.gamemode = packet.gamemode & 0x7
        server.hardcore = packet.gamemode & 0x8 != 0
        server.difficulty = packet.difficulty
        server.level_type = packet.level_type

    @client.packet_handler(client.input_protocol.play.UpdateSign)
    def handle_update_sign(packet):
        server.signs.append({
            'x': packet.location[0],
            'y': packet.location[1],
            'z': packet.location[2],
            'lines': [
                util.parse_chat(packet.line_1),
                util.parse_chat(packet.line_2),
                util.parse_chat(packet.line_3),
                util.parse_chat(packet.line_4)
            ]
        })

    server.state = "start"
    client.start()
    server.state = "login"
    client.login(authenticator or _AUTHENTICATOR)

    server.state = "whitelist"
    try:
        if client.wait_for_packet(client.input_protocol.login.LoginSuccess):
            server.whitelist = False
        elif not server.error:
            server.error = "Did not receive login success packet"
            return
    except network.DisconnectException as e:
        for pattern in ("whitelist", "white-list"):
            if pattern in e.message.lower():
                server.whitelist = True
        raise

    server.state = "world load"
    client.wait_for_world_load()

    # Wait until after potential welcome messages
    INVALID_RESPONSES = (
        "you do not have permission",
        "not allowed",
        "<commands.generic.notfound()>"
    )

    packets = client.wait_for_multiple(client.input_protocol.play.ChatMessage,
                             timeout=1)
    server.welcome = parse_packet_messages(packets, INVALID_RESPONSES)

    server.state = "plugins"
    client.send(client.output_protocol.play.ChatMessage(message="/plugins"))
    packets = client.wait_for_multiple(client.input_protocol.play.ChatMessage,
                                       timeout=0.5)
    server.plugins = parse_packet_messages(packets, INVALID_RESPONSES)

    gevent.sleep(5)  # Many servers don't accept commands in quick succession

    server.state = "version"
    client.send(client.output_protocol.play.ChatMessage(message="/version"))
    packets = client.wait_for_multiple(client.input_protocol.play.ChatMessage,
                                       timeout=0.5)
    server.software = parse_packet_messages(packets, INVALID_RESPONSES)

    gevent.sleep(1)  # Many servers don't accept commands in quick succession
    server.state = "help"
    client.send(client.output_protocol.play.ChatMessage(message="/help"))
    packets = client.wait_for_multiple(client.input_protocol.play.ChatMessage,
                                       timeout=0.5)
    server.help_p1 = parse_packet_messages(packets, INVALID_RESPONSES)


def server_info_map(servers, pool_size=10, authenticator=None):
    global _AUTHENTICATOR

    _AUTHENTICATOR = authenticator or authentication.AuthenticatorPool()

    pool = gevent.pool.Pool(pool_size)
    for server in pool.imap_unordered(get_server_info, servers):
        yield server

    _AUTHENTICATOR = None


class ServerInfo(status.ServerStatus):
    WHITELIST_MAP = {
        True: "on",
        False: "off",
        None: "unknown"
    }

    DIFFICULTY_MAP = {
        0: "peaceful",
        1: "easy",
        2: "normal",
        3: "hard"
    }

    GAMEMODE_MAP = {
        0: "survival",
        1: "creative",
        2: "adventure",
        3: "spectator"
    }

    def __init__(self, addr, id_=None, logfile=None):
        super(ServerInfo, self).__init__(addr, id_, logfile=logfile)
        self.whitelist = None
        self.plugins = None
        self.software = None
        self.brand = None
        self.welcome = None
        self.help_p1 = None
        self.gamemode = None
        self.hardcore = None
        self.difficulty = None
        self.level_type = None
        self.signs = []

    def __unicode__(self):
        lines = super(ServerInfo, self).__unicode__().split("\n")

        def format_signs(signs):
            return "".join(
                "\n    [% 5d, % 3d, % 5d]: %s" %
                (sign['x'], sign['y'], sign['z'], " ".join(
                    line.strip() for line in sign['lines']
                ))
                for sign in signs
            )

        attrs = [
            ("whitelist", "whitelist", lambda v: self.WHITELIST_MAP[v]),
            ("software", "software version"),
            ("brand",),
            ("plugins",),
            ("welcome", "welcome message"),
            ("help_p1", "help page 1"),
            ("gamemode", "game mode", lambda v: self.GAMEMODE_MAP[v]),
            ("hardcore",),
            ("difficulty", "difficulty", lambda v: self.DIFFICULTY_MAP[v]),
            ("level_type",),
            ("signs", "signs", format_signs)
        ]

        for attr in attrs:
            value = getattr(self, attr[0])
            title = attr[1] if len(attr) > 1 else attr[0]

            if len(attr) > 2:
                value = attr[2](value)

            lines.append("  %s: %s" % (title, value))

        return "\n".join(lines)

    def __str__(self):
        return unicode(self).encode("utf8")


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)

    host = "localhost"
    port = 25565

    if "--debug" in sys.argv:
        ## TODO: Use argparse
        sys.argv.remove("--debug")
        logfile = "/tmp/mc4p.log"
    else:
        logfile = None

    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Error: Couldn't parse port")
            sys.exit(1)

    if len(sys.argv) >= 2:
        host = sys.argv[1]

    print(get_server_info((host, port), logfile=logfile))
