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

def mcorgrow(row):
    host = row[4]
    port = None
    id_ = None
    try:
        port = int(row[5])
        id_ = int(row[0])
    except ValueError:
        pass
    return host, port, id_

def iprow(row):
    saddr = row[0].lower() ### standardize case
    saddr = saddr.replace('\n', '') #### bc some addresses have a newline for some reason## some
    host = saddr.partition(':')[0]
    port = 25565
    ### if there is no port, or only a default port, 
    ###  then report the name/ip of the server plain.  
    ###  if there is a special port, leave it in the name.  
    ###  that way an ip can serve multiple servers and I 
    ###  measure each of them separately.
    if saddr.partition(':')[2] == '' or  saddr.partition(':')[2] == '25565':  
        pass
    else: 
        port = saddr.partition(':')[2]
    return(host, port, None)

def main():
    """
    Reads servers from a CSV file and queries them for various properties
    """
    if len(sys.argv) >= 3:
        logdir = sys.argv[2]
    else:
        logdir = None

    servers = {}
    with open(sys.argv[1]) as f:
        reader = csv.reader(f, escapechar=b"\\", doublequote=False)
        for i, row in enumerate(reader):
            #host, port, id_ = mcorgrow(row)
            host, port, id_ = iprow(row)
            if not id_: id_ = i
            if not port: continue

            if logdir:
                logfile = os.path.join(logdir, "%05d.log" % id_)
            else:
                logfile = None

            servers[(host,port,id_)] = info.ServerInfo((host, port), id_, logfile=logfile)

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

    for i in range(50):
        for server in info.server_info_map(servers.values(), pool_size=19,
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
                "welcome",
                "help_p1",
                "brand",
                "state",
                "error"
            ))
            print(json.dumps(data))

            ### remove servers that I heard from and keep trying on the others
            if data['whitelist'] != None:
              del servers[(data['host'], data['port'], data['id'])]
        print("pass", i, ": ", len(servers.keys))


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)

    import cProfile
    cProfile.run("main()", "/tmp/stats.dat")
