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
        server = ServerInfo(server, logfile=logfile)

    try:
        _get_server_info(server, authenticator=authenticator)
    except Exception as e:
        server.error = str(e)
        if raise_errors:
            raise
        logger.error("Could not connect to %s: %s" % (repr(server), str(e)))

    return server


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
    client.wait_for_multiple(client.input_protocol.play.ChatMessage,
                             timeout=1)

    INVALID_RESPONSES = (
        "you do not have permission",
        "not allowed",
        "<commands.generic.notfound()>"
    )

    server.state = "plugins"
    client.send(client.output_protocol.play.ChatMessage(message="/plugins"))
    packets = client.wait_for_multiple(client.input_protocol.play.ChatMessage,
                                       timeout=0.5)
    if packets:
        plugins = " ".join(
            util.parse_chat(packet.message) for packet in packets
        )

        for invalid_response in INVALID_RESPONSES:
            if invalid_response in plugins.lower():
                break
        else:
            server.plugins = plugins

    gevent.sleep(5)  # Many servers don't accept commands in quick succession

    server.state = "version"
    client.send(client.output_protocol.play.ChatMessage(message="/version"))
    packets = client.wait_for_multiple(client.input_protocol.play.ChatMessage,
                                       timeout=0.5)
    if packets:
        software = " ".join(
            util.parse_chat(packet.message) for packet in packets
        )

        for invalid_response in INVALID_RESPONSES:
            if invalid_response in software:
                break
        else:
            server.software = software


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

    def __init__(self, addr, id_=None, logfile=None):
        super(ServerInfo, self).__init__(addr, id_, logfile=logfile)
        self.whitelist = None
        self.plugins = None
        self.software = None
        self.brand = None

    def __unicode__(self):
        lines = super(ServerInfo, self).__unicode__().split("\n")

        if self.whitelist is not None:
            lines.append("  whitelist: " + self.WHITELIST_MAP[self.whitelist])

        if self.software is not None:
            lines.append("  software version: " + self.software)

        if self.brand is not None:
            lines.append("  brand: " + self.brand)

        if self.plugins is not None:
            lines.append("  plugins: " + self.plugins)

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
