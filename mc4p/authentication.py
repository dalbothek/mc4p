# -*- coding: utf-8 -*-

# This source file is part of mc4p,
# the Minecraft Portable Protocol-Parsing Proxy.
#
# Copyright (C) 2011 Matthew J. McGill, Simon Marti

# This program is free software. It comes without any warranty, to
# the extent permitted by applicable law. You can redistribute it
# and/or modify it under the terms of the Do What The Fuck You Want
# To Public License, Version 2, as published by Sam Hocevar. See
# http://sam.zoy.org/wtfpl/COPYING for more details

import requests
import sys
import os
from time import time
from hashlib import sha1
from struct import unpack

from encryption import encode_public_key, PBEWithMD5AndDES


class Authenticator(object):
    LOGIN_URL = 'https://login.minecraft.net'
    SESSION_URL = 'http://session.minecraft.net/game/joinserver.jsp'
    CHECK_SESSION_URL = 'http://session.minecraft.net/game/checkserver.jsp'
    VERSION = 1337

    def __init__(self, username, password):
        self.user = username
        self.password = password
        self._session = None
        self._login_time = 0

    def check(self):
        """Checks if the credentials are valid"""
        return self._get_session_id() is not None

    def join_server(self, server_id, shared_secret, public_key):
        r = requests.get(self.SESSION_URL,
                         params={'user': self.player_name(),
                                 'sessionId': self._get_session_id(),
                                 'serverId': self.login_hash(server_id,
                                                             shared_secret,
                                                             public_key)})

    def player_name(self):
        if self._get_session() is None:
            return None
        return self._get_session()[2]

    def _get_session(self):
        """Authenticates a player"""
        if self._session is None or self._login_time < time() - 50:
            r = requests.post(self.LOGIN_URL,
                              data={'user': self.user,
                                    'password': self.password,
                                    'version': self.VERSION})
            if r.ok and len(r.content.split(":")) >= 4:
                self._session = r.content.split(":")
                self._login_time = time()
        return self._session

    def _get_session_id(self):
        if self._get_session() is None:
            return None
        return self._get_session()[3].strip()

    @classmethod
    def check_player(cls, username, server_id, shared_secret, public_key):
        """Checks if a user is allowed to join the server."""
        return cls._check_player(username, cls.login_hash(server_id,
                                                          shared_secret,
                                                          public_key))

    @classmethod
    def _check_player(cls, username, session_hash):
        r = requests.get(cls.CHECK_SESSION_URL,
                         params={'user': username, 'serverId': session_hash})
        return r.ok and r.content.strip() == "YES"

    @staticmethod
    def login_hash(server_id, shared_secret, public_key):
        """Returns the server id which is then used for joining a server"""
        digest = sha1()
        digest.update(server_id)
        digest.update(shared_secret)
        digest.update(encode_public_key(public_key))
        d = long(digest.hexdigest(), 16)
        if d >> 39 * 4 & 0x8:
            return "-%x" % ((-d) & (2 ** (40 * 4) - 1))
        return "%x" % d


def minecraft_credentials():
    path = os.path.join(_minecraft_folder(), "lastlogin")
    try:
        with open(path) as f:
            ciphertext = f.read()
    except IOError:
        return None
    plaintext = PBEWithMD5AndDES('passwordfile').decrypt(ciphertext)
    user_size = unpack(">h", plaintext[:2])[0]
    user = plaintext[2:user_size + 2]
    password_size = unpack(">h", plaintext[2 + user_size:4 + user_size])[0]
    password = plaintext[4 + user_size:]
    return user, password


def _minecraft_folder():
    """Finds the folder minecraft stores the account credentials in.

    Copyright (c) 2010 David Rio Vierra

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.
    """
    if sys.platform == "win32":
        try:
            import win32com.client
            objShell = win32com.client.Dispatch("WScript.Shell")
            appDataDir = objShell.SpecialFolders("AppData")
        except Exception, e:
            try:
                from win32com.shell import shell, shellcon
                appDataDir = shell.SHGetPathFromIDListEx(
                    shell.SHGetSpecialFolderLocation(0, shellcon.CSIDL_APPDATA)
                )
            except Exception, e:
                appDataDir = os.environ['APPDATA'].decode(
                    sys.getfilesystemencoding()
                )
        minecraftDir = os.path.join(appDataDir, u".minecraft")
    elif sys.platform == "darwin":
        appDataDir = os.path.expanduser(u"~/Library/Application Support")
        minecraftDir = os.path.join(appDataDir, u"minecraft")
        minecraftDir.decode(sys.getfilesystemencoding())
    else:
        appDataDir = os.path.expanduser(u"~")
        minecraftDir = os.path.expanduser(u"~/.minecraft")
    return minecraftDir


if __name__ == "__main__":
    print minecraft_credentials()
