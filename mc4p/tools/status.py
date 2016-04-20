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

import sys
import logging

from mc4p import network
from mc4p import protocol
from mc4p import util


logger = logging.getLogger("status")


def server_status(server, raise_errors=False):
    if not isinstance(server, ServerStatus):
        server = ServerStatus(server)

    try:
        _server_status(server)
    except Exception as e:
        server.online = False
        server.error = str(e)
        if raise_errors:
            raise
        logger.error("Could not connect to %s: %s" % (repr(server), str(e)))

    return server


def _server_status(server):
    """Pings a server for its status"""

    server.state = "connect"
    client = network.Client(server.addr, logfile=server.logfile)

    server.state = "start"
    client.start()

    server.state = "handshake"
    client.send_handshake(protocol.State.status)

    server.state = "status request"
    client.send(client.output_protocol.status.Request())

    packet = client.wait_for_packet(client.input_protocol.status.Response)
    client.close()

    if packet:
        server.status_packet(packet)

    return server


class ServerStatus(object):
    def __init__(self, addr, id_=None, logfile=None):
        self.addr = addr
        self.host, self.port = addr
        self.id = id_
        self.online = None
        self.player_count = None
        self.max_player_count = None
        self.players = None
        self.version = None
        self.protocol_version = None
        self.description = None
        self.error = None
        self.state = None
        self.logfile = logfile

    @classmethod
    def from_status_packet(cls, status_packet):
        status = cls()
        status.status_packet(status_packet)
        return status

    def status_packet(self, status_packet):
        self.online = True
        status = status_packet.status

        if "players" in status:
            self.player_count = status['players'].get("online")
            self.max_player_count = status['players'].get("max")
            if "sample" in status['players']:
                self.players = [
                    player['name'] for player in status['players']['sample']
                ]

        if "version" in status:
            self.version = util.strip_color(status['version'].get("name"))
            self.protocol_version = status['version'].get("protocol")

        if "description" in status:
            self.raw_description = status['description']
            self.description = util.parse_chat(status['description'])

    def __repr__(self):
        if self.id is not None:
            return "Server(%d, %s:%d)" % (self.id, self.host, self.port)
        else:
            return "Server(%s:%d)" % self.addr

    def __unicode__(self):
        lines = []
        if self.id is not None:
            lines.append("ServerStatus (id: %d):" % self.id)
        else:
            lines.append("ServerStatus")

        lines.append("  address: %s:%d" % self.addr)

        if self.online is None:
            lines.append("  status: unknown")
        elif not self.online:
            lines.append("  status: offline")
        else:
            lines.append("  status: online")

        if self.player_count is not None:
            lines.append("  players: %d/%d" % (
                self.player_count, self.max_player_count
            ))

        if self.version is not None or self.protocol_version is not None:
            lines.append("  version: %s (protocol %d)" % (
                self.version, self.protocol_version
            ))

        if self.description is not None:
            lines.append("  description: %s" % self.description)

        return "\n".join(lines)

    def __str__(self):
        return unicode(self).encode("utf8")


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)

    host = "localhost"
    port = 25565

    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Error: Couldn't parse port")
            sys.exit(1)

    if len(sys.argv) >= 2:
        host = sys.argv[1]

    print(server_status((host, port), raise_errors=True))
