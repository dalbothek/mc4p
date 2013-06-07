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


from sys import version_info
from setuptools import setup, find_packages

basename = "mc4p"
version = "1.0"
pyversion = "%s.%s" % (version_info.major, version_info.minor)

setup(
    name=basename,
    version=version,
    packages=find_packages(),
    zip_safe=False,
    test_suite='test_plugins',
    author="Simon Marti",
    author_email="simon.marti@ceilingcat.ch",
    description="Pluggable Minecraft proxy",
    keywords="minecraft proxy",
    url="https://github.com/sadimusi/mc4p",
    install_requires=("gevent", "pycrypto", "requests", "certifi", "blessings")
)
