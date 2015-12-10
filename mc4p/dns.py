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

import re
import time

import gevent.monkey

gevent.monkey.patch_all(thread=False)

import dns.resolver


IP_PATTERN = re.compile("(\d{1,3}\.){3}\d{1,3}\.?")
DNS_CACHE = {}
TTL = 60 * 60


def resolve(host, port=25565):
    if host == "localhost":
        return host, port

    if (host, port) in DNS_CACHE:
        cached, cache_time = DNS_CACHE[host, port]
        if cache_time + TTL > time.time():
            return cached

    addr = _resolve(host, port)
    DNS_CACHE[(host, port)] = (addr, time.time())
    return addr


def _resolve(host, port):
    # Resolve SRV records
    if not IP_PATTERN.match(host):
        try:
            srv = dns.resolver.query("_minecraft._tcp.%s" % host, "SRV")
        except:
            pass
        else:
            host = str(srv[0].target)
            port = srv[0].port

    # Resolve A and CNAME records
    for i in range(10):
        if IP_PATTERN.match(host):
            break

        try:
            a = dns.resolver.query(host)
        except:
            return None
        host = str(a[0].address)

    if host.endswith("."):
        host = host[:-1]

    return host, port
