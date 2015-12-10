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

from mc4p import network
from mc4p import protocol


logger = logging.getLogger("proxy")


class ProxyServer(network.Server):
    def __init__(self, addr, remote_addr):
        super(ProxyServer, self).__init__(addr, ProxyClientHandler)
        self.remote_addr = remote_addr


class ProxyClientHandler(network.ClientHandler):
    def init(self):
        self.client = ProxyClient(self.server.remote_addr, self)
        self.client.start()

    def handle_disconnect(self):
        logger.info("%s disconnected" % self)
        self.client.close()

    def handle_packet(self, packet):
        print("C->S")
        packet._show()
        # TODO: Remove magic id
        if packet._state != protocol.State.login or packet.id != 1:
            self.client.send(packet)

    def handle_packet_error(self, error):
        logger.error("%s caused an error: %s" % (self, error))
        self.close()
        return True

    def __str__(self):
        return "Client %s:%d" % self.addr


class ProxyClient(network.Client):
    def __init__(self, addr, server):
        super(ProxyClient, self).__init__(addr, version=0)
        self.server = server

    def handle_packet(self, packet):
        print("S->C")
        packet._show()
        # TODO: Remove magic id
        if packet._state != protocol.State.login or packet.id != 1:
            self.server.send(packet)

    def handle_disconnect(self):
        logger.info("%s disconnected" % self)
        self.server.close()

    def __str__(self):
        return "Server %s:%d" % self.addr


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    server = ProxyServer(("", 25566), ("localhost", 25565))
    import cProfile
    cProfile.run("server.run()", "/tmp/stats.dat")
