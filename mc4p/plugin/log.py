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


# Message logging plugin, by fredreichbier


from mc4p.plugins import MC4Plugin
from mc4p.messages import cli_msgs, srv_msgs

IGNORE = ['mgstype']
SHORTEN = ['chunk', 'chunks', 'raw_bytes']

class LogPlugin(MC4Plugin):
    def default_handler(self, msg, source):
        line = []
        msgs = srv_msgs # TODO

        if source == 'server':
            line.append('Server -> Client')
            msgs = srv_msgs
        elif source == 'client':
            line.append('Client -> Server')
            msgs = cli_msgs
        else:
            line.append('from %s' % source)

        try:
            parsem = msgs[msg['msgtype']]
            name = parsem.name
        except ValueError:
            name = 'Unknown'

        line.append('0x%.2x (%s)' % (msg['msgtype'], name))
        line.append('%d bytes' % len(msg['raw_bytes']))
        print ' '.join(line)
        for key, value in msg.iteritems():
            if key not in IGNORE:
                if key in SHORTEN:
                    print '    %s: ...' % key
                else:
                    print '    %s: %r' % (key, value)
        print
        return True

