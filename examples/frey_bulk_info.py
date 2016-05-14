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

from os import path, remove

import logging
import json
import sys
import csv
from time import sleep, time
from datetime import datetime

from mc4p.tools import info
from mc4p import authentication

logger = logging.getLogger("info")
logger.setLevel(logging.INFO)

def mcorgrow(row):
    host = row[4]
    port = None
    id_ = None
    try:
        port = int(row[5])
    except ValueError:
        pass
    try:
        id_ = int(row[0])
    except ValueError:
        pass
    return host, port, id_

def iprow(row):
    saddr = row[0].lower() ### standardize case
    saddr = saddr.replace('\n', '') #### bc some addresses have a newline for some reason## some
    if saddr.count(':') > 1: return((False, False, False)) ### this means it's not an IP that I know how to resolve

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
        #print(saddr.partition(':'))
        port = int(saddr.partition(':')[2])
    return(host, port, None)

def main():
    """
    Reads servers from a CSV file and queries them for various properties
    """

    if len(sys.argv) >= 3:
        logdir = sys.argv[2]
    else:
        logdir = 'log'

    ### reset success file
    if False: ## I should delete sniff_failures when the script has made a full full pass and I want to run it all over again (on servers I havent' hit yet)
        try:
            remove(path.join(logdir , 'sniff_failures.txt'))
        except OSError:
            pass

    servers = {}
    skip_list =       open(path.join(logdir , 'sniff_failures.txt'), 'r').readlines()
    skip_list.extend( open(path.join(logdir, 'sniff_successes.txt'), 'r').readlines() )
    skip_list = [ ip.strip() for ip in skip_list ]
    with open(sys.argv[1]) as f:
        reader = csv.reader(f, escapechar=b"\\", doublequote=False)
        for i, row in enumerate(reader):
            #host, port, id_ = mcorgrow(row)
            host, port, id_ = iprow(row)
            if not host: continue
            if not id_: id_ = i
            if not port: continue
            if host+':'+str(port) in skip_list: continue

            ### if I want to maintain this, I'm going to have to do something tomanage the fact of 1000000s of log files, some of them huge
            #if logdir:
                #logfile = path.join(logdir, "%05d.log" % id_)
            #else:
                #logfile = None

            #servers[(host,port,id_)] = info.ServerInfo((host, port), id_, logfile=logfile)
            servers[(host,port,id_)] = (host,port,id_)
    # For testing you might want to use a smaller number of servers
    # servers = servers[:200]

    authenticator = None

    # If minecraft isn't installed on this machine you need to specify
    # a configuration file manually. Just copy over the launcher_profiles.json
    # from your local minecraft installation and mc4p will be able to log in
    # with your game accounts.
    if True:
        authenticator = authentication.AuthenticatorPool(
            config_path="/home/sethfrey/.minecraft/launcher_profiles.json"
        )

    ### number of iterations through the whole list
    for i in range(10):
        for server in info.server_info_map(servers.values(), pool_size=16,
                                          authenticator=authenticator):
            logger.info(server.host+':'+str(server.port))
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
                "plugins_fml",
                "software",
                "welcome",
                "help_p1",
                "brand",
                "gamemode",
                "hardcore",
                "difficulty",
                "level_type",
                "signs",
                "state",
                "error"
            ))
            if data['online']:
                print(json.dumps(data))

            ### remove servers that I heard from and keep trying on the others
            if data['whitelist'] != None or data['online']:
              with open(path.join(logdir, 'sniff_successes.txt'), 'a') as successlog:
                successlog.write("%s:%d\n"%(data['host'],data['port']))
              del servers[(data['host'], data['port'], data['id'])]
            else:
              with open(path.join(logdir, 'sniff_failures.txt'), 'a') as failurelog:
                failurelog.write("%s:%d\n"%(data['host'],data['port']))
        logger.info(datetime.fromtimestamp(time()).strftime('%Y-%m-%d %H:%M:%S'), " PASS", i, ": ", len(servers.keys()), "remaining")
        sleep(60)


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)

    import cProfile
    cProfile.run("main()", "/tmp/stats.dat")
