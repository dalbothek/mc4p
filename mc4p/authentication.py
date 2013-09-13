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

import os
import sys
import json
import time
import struct
import hashlib

import requests

import encryption


class Authenticator(object):
    SESSION_URL = 'http://session.minecraft.net/game/joinserver.jsp'
    CHECK_SESSION_URL = 'http://session.minecraft.net/game/checkserver.jsp'
    VALID_TIME = 60 * 60

    username = None
    session_id = None
    display_name = None
    __last_auth_time = 0

    def authenticate(self):
        if self.__last_auth_time + self.VALID_TIME < time.time():
            self._authenticate()
            self.__last_auth_time = time.time()

    def valid(self):
        try:
            self.authenticate()
        except:
            return False
        else:
            return True

    def _authenticate(self):
        raise NotImplementedError

    def join_server(self, server_id, shared_secret, public_key):
        self.authenticate()
        requests.get(self.SESSION_URL,
                     params={'user': self.display_name,
                             'sessionId': self.session_id,
                             'serverId': self.__login_hash(server_id,
                                                           shared_secret,
                                                           public_key)})

    @classmethod
    def check_player(cls, username, server_id, shared_secret, public_key):
        """Checks if a user is allowed to join the server."""
        return cls.__check_player(username, cls.__login_hash(server_id,
                                                             shared_secret,
                                                             public_key))

    @staticmethod
    def _minecraft_folder():
        """Finds the folder minecraft stores the account credentials in.

        Copyright (c) 2010 David Rio Vierra

        Permission to use, copy, modify, and/or distribute this software for
        any purpose with or without fee is hereby granted, provided that the
        above copyright notice and this permission notice appear in all copies.
        """
        if sys.platform == "win32":
            try:
                import win32com.client
                objShell = win32com.client.Dispatch("WScript.Shell")
                appDataDir = objShell.SpecialFolders("AppData")
            except:
                try:
                    from win32com.shell import shell, shellcon
                    appDataDir = shell.SHGetPathFromIDListEx(
                        shell.SHGetSpecialFolderLocation(
                            0, shellcon.CSIDL_APPDATA
                        )
                    )
                except:
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

    @classmethod
    def __check_player(cls, username, session_hash):
        r = requests.get(cls.CHECK_SESSION_URL,
                         params={'user': username, 'serverId': session_hash})
        return r.ok and r.content.strip() == "YES"

    @staticmethod
    def __login_hash(server_id, shared_secret, public_key):
        """Returns the server id which is then used for joining a server"""
        digest = hashlib.sha1()
        digest.update(server_id)
        digest.update(shared_secret)
        digest.update(encryption.encode_public_key(public_key))
        d = long(digest.hexdigest(), 16)
        if d >> 39 * 4 & 0x8:
            return "-%x" % ((-d) & (2 ** (40 * 4) - 1))
        return "%x" % d


class OldLoginAuthenticator(Authenticator):
    LOGIN_URL = 'https://login.minecraft.net'
    VERSION = 1337
    VALID_TIME = 60

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def _authenticate(self):
        r = requests.post(self.LOGIN_URL,
                          data={'user': self.username,
                                'password': self.password,
                                'version': self.VERSION})
        if not r.ok:
            r.raise_for_status()
        if len(r.content.split(":")) < 4:
            raise Exception("Invalid response from server: " + r.content)
        reponse = r.content.split(":")
        self.display_name = reponse[2]
        self.session_id = reponse[3].strip()

    def __repr__(self):
        return ("OldLoginAuthenticator(user:'%s', player:'%s')" %
                (self.username, self.display_name))


class LastLoginAuthenticator(OldLoginAuthenticator):
    def __init__(self):
        path = os.path.join(self._minecraft_folder(), "lastlogin")
        with open(path) as f:
            ciphertext = f.read()
        cipher = encryption.PBEWithMD5AndDES('passwordfile')
        plaintext = cipher.decrypt(ciphertext)
        user_size = struct.unpack(">h", plaintext[:2])[0]
        username = plaintext[2:user_size + 2]
        password = plaintext[4 + user_size:]
        super(LastLoginAuthenticator, self).__init__(username, password)

    def __repr__(self):
        return ("LastLoginAuthenticator(user:'%s', player:'%s')" %
                (self.username, self.display_name))


class YggdrasilAuthenticator(Authenticator):
    YGGDRASIL_URL = "https://authserver.mojang.com/"
    AUTH_URL = YGGDRASIL_URL + "authenticate"
    REFRESH_URL = YGGDRASIL_URL + "refresh"
    VALIDATE_URL = YGGDRASIL_URL + "validate"
    INVALIDATE_URL = YGGDRASIL_URL + "invalidate"
    SIGNOUT_URL = YGGDRASIL_URL + "signout"

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.client_token = self._random_token()

    @property
    def session_id(self):
        self.authenticate()
        return "token:%s:%s" % (self.access_token, self.uuid)

    def _authenticate(self):
        r = self._request(self.AUTH_URL, {
            'agent': {
                'name': "Minecraft",
                'version': 1
            },
            'username': self.username,
            'password': self.password,
            'clientToken': self.client_token
        })
        self.access_token = r['accessToken']
        self.display_name = r['selectedProfile']['name']
        self.uuid = r['selectedProfile']['id']

    def _request(self, url, data):
        r = requests.post(url, data=json.dumps(data))
        response = json.loads(r.content) if r.content else None
        if not r.ok:
            raise self.YggdrasilException(response)
        return response

    def __repr__(self):
        return ("YggdrasilAuthenticator(user:%s, player:%s)" %
                (self.username, self.display_name))

    @classmethod
    def _random_token(cls):
        return "".join("%02x" % ord(c) for c in encryption.generate_random_bytes(16))

    class YggdrasilException(Exception):
        def __init__(self, r):
            super(YggdrasilAuthenticator.YggdrasilException, self).__init__(
                r.get('errorMessage')
            )
            self.error = r.get('error')
            self.cause = r.get('cause')

        def __str__(self):
            error = "%s: %s" % (self.error, self.message)
            if self.cause:
                return "%s (cause: %s)" % (error, self.cause)
            else:
                return error


class YggdrasilTokenAuthenticator(YggdrasilAuthenticator):
    def __init__(self, profile=None):
        config = self._config()
        if profile is None:
            profile = config['selectedProfile']
        self.profile = profile
        profile = config['profiles'][profile]
        self.uuid = profile['playerUUID']
        auth = config['authenticationDatabase'][self.uuid]
        self.username = auth['username']
        self.access_token = auth['accessToken']
        self.display_name = auth['displayName']
        self.client_token = config['clientToken']

    def _authenticate(self):
        self._request(self.VALIDATE_URL, {
            'accessToken': self.access_token
        })

    @classmethod
    def _config(cls):
        with open(cls._config_path()) as f:
            return json.load(f)

    @classmethod
    def _config_path(cls):
        return os.path.join(cls._minecraft_folder(), "launcher_profiles.json")


def AuthenticatorFactory():
    for authenticator in (YggdrasilTokenAuthenticator, LastLoginAuthenticator):
        try:
            authenticator = authenticator()
            authenticator.authenticate()
        except:
            continue
        else:
            return authenticator


if __name__ == "__main__":
    print LastLoginAuthenticator().password
