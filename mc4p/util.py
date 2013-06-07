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

import os.path, logging, logging.config

class PartialPacketException(Exception):
    """Thrown during parsing when not a complete packet is not available."""
    pass


class Stream(object):
    """Represent a stream of bytes."""

    def __init__(self):
        """Initialize the stream."""
        self.buf = ""
        self.i = 0
        self.tot_bytes = 0
        self.wasted_bytes = 0

    def append(self,str):
        """Append a string to the stream."""
        self.buf += str

    def read(self,n):
        """Read n bytes, returned as a string."""
        if self.i + n > len(self.buf):
            self.wasted_bytes += self.i
            self.i = 0
            raise PartialPacketException()
        str = self.buf[self.i:self.i+n]
        self.i += n
        return str

    def reset(self):
        self.i = 0

    def packet_finished(self):
        """Mark the completion of a packet, and return its bytes as a string."""
        # Discard all data that was read for the previous packet,
        # and reset i.
        data = ""
        if self.i > 0:
            data = self.buf[:self.i]
            self.buf = self.buf[self.i:]
            self.tot_bytes += self.i
            self.i = 0
        return data

    def __len__(self):
        return len(self.buf) - self.i

def write_default_logging_file(lpath):
    """Write a default logging.conf."""
    contents="""
[loggers]
keys=root,mc4p,plugins,parsing

[handlers]
keys=consoleHdlr

[formatters]
keys=defaultFormatter

[logger_root]
level=WARN
handlers=consoleHdlr

[logger_mc4p]
handlers=
qualname=mc4p

[logger_plugins]
handlers=
qualname=plugins

[logger_parsing]
handlers=
qualname=parsing

[handler_consoleHdlr]
class=StreamHandler
formatter=defaultFormatter
args=(sys.stdout,)

[formatter_defaultFormatter]
format=%(levelname)s|%(asctime)s|%(name)s - %(message)s
datefmt=%H:%M:%S
"""
    f=None
    try:
        f=open(lpath,"w")
        f.write(contents)
    finally:
        if f: f.close()

logging_configured = False

def config_logging(logfile=None):
    """Configure logging. Can safely be called multiple times."""
    global logging_configured
    if not logging_configured:
        dir = os.path.dirname(os.path.abspath(__file__))
        if not logfile:
            logfile = os.path.join(dir, 'logging.conf')
        if not os.path.exists(logfile):
            write_default_logging_file(logfile)
        logging.config.fileConfig(logfile)
        logging_configured = True

