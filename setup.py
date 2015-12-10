# -*- coding: utf-8 -*-

# This source file is part of mc4p,
# the Minecraft Portable Protocol-Parsing Proxy.

# This program is free software. It comes without any warranty, to
# the extent permitted by applicable law. You can redistribute it
# and/or modify it under the terms of the Do What The Fuck You Want
# To Public License, Version 2, as published by Sam Hocevar. See
# http://www.wtfpl.net/txt/copying/ for more details

import setuptools


setuptools.setup(
    name="mc4p",
    version="2.0",
    packages=setuptools.find_packages(),
    zip_safe=True,
    author="Simon Marti",
    author_email="simon@marti.email",
    description="Minecraft protocol utilities",
    keywords="minecraft protocol proxy",
    url="https://github.com/sadimusi/mc4p",
    install_requires=("gevent", "geventhttpclient", "certifi", "pycrypto"),
    extras_require = {
        'performance': ("pycrypto",),
        'formatting': ("blessings",)
    }
)
