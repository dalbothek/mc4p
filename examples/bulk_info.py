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

import os.path

import logging
import json
import sys
import csv

from mc4p.tools import info
from mc4p import authentication


def main():
    """
    Reads servers from a CSV file and queries them for various properties
    """
    if len(sys.argv) >= 3:
        logdir = sys.argv[2]
    else:
        logdir = None

    servers = []
    with open(sys.argv[1]) as f:
        reader = csv.reader(f, escapechar=b"\\", doublequote=False)
        for row in reader:
            host = row[4]
            try:
                port = int(row[5])
                id_ = int(row[0])
            except ValueError:
                continue

            if logdir:
                logfile = os.path.join(logdir, "%05d.log" % id_)
            else:
                logfile = None

            servers.append(info.ServerInfo((host, port), id_, logfile=logfile))

    # For testing you might want to use a smaller number of servers
    # servers = servers[:200]

    authenticator = None

    # If minecraft isn't installed on this machine you need to specify
    # a configuration file manually. Just copy over the launcher_profiles.json
    # from your local minecraft installation and mc4p will be able to log in
    # with your game accounts.
    if False:
        authenticator = authentication.AuthenticatorPool(
            config_path="launcher_profiles.json"
        )

    for server in info.server_info_map(servers, pool_size=20,
                                       authenticator=authenticator):
        data = dict((key, getattr(server, key)) for key in (
            "host",
            "port",
            "id",
            "online",
            "player_count",
            "max_player_count",
            "players",
            "version",
            "protocol_version",
            "description",
            "whitelist",
            "plugins",
            "software",
            "brand",
            "gamemode",
            "hardcore",
            "difficulty",
            "level_type",
            "signs",
            "state",
            "error"
        ))
        print(json.dumps(data))


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)

    import cProfile
    cProfile.run("main()", "/tmp/stats.dat")
