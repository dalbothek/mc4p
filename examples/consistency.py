# -*- coding: utf-8 -*-

# This source file is part of mc4p,
# the Minecraft Portable Protocol-Parsing Proxy.

# This program is free software. It comes without any warranty, to
# the extent permitted by applicable law. You can redistribute it
# and/or modify it under the terms of the Do What The Fuck You Want
# To Public License, Version 2, as published by Sam Hocevar. See
# http://www.wtfpl.net/txt/copying/ for more details


import json
import sys
import os.path


KEYS = ("online", "whitelist", "error")


def check_consistency(folder):
    """
    The idea here is to read multiple files from a directory with each file
    containing one json-encoded server info object per line. The infos of each
    server are aggregated and compared against each other.
    """
    servers = {}

    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        if os.path.isfile(path):
            with open(path) as f:
                for line in f:
                    try:
                        server = json.loads(line)
                    except ValueError:
                        continue

                    servers.setdefault(server['id'], []).append(server)

    for server in servers.itervalues():
        key = inconsistent_key(server)
        if key:
            print(key)
            for round_ in server:
                print(" ".join(
                    "%s: %s" % (key, round_[key]) for key in KEYS
                ))
            print("\n".join(str(round_) for round_ in server))
            print("")


def inconsistent_key(rounds):
    first_round = rounds[0]

    for round_ in rounds:
        for key in KEYS:
            if round_[key] != first_round[key]:
                return key


if __name__ == "__main__":
    check_consistency(sys.argv[1])
