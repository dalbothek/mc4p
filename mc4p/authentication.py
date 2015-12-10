# -*- coding: utf-8 -*-

# This source file is part of mc4p,
# the Minecraft Portable Protocol-Parsing Proxy.

# This program is free software. It comes without any warranty, to
# the extent permitted by applicable law. You can redistribute it
# and/or modify it under the terms of the Do What The Fuck You Want
# To Public License, Version 2, as published by Sam Hocevar. See
# http://www.wtfpl.net/txt/copying/ for more details

import os
import sys
import json
import time
import hashlib
import collections

import certifi
import geventhttpclient.url

from mc4p import encryption


class OfflinePlayer(object):
    def __init__(self, username):
        self.username = username
        self.display_name = username

    def join_server(self, server_id, shared_secret, public_key, wait=False):
        raise AuthenticationException(
            "Offline player tried to join online server"
        )

    def get(self):
        return self


class Authenticator(object):
    SESSION_URL = "https://sessionserver.mojang.com"
    JOIN_URL = "/session/minecraft/join"
    HAS_JOINED_URL = "/session/minecraft/hasJoined"

    YGGDRASIL_URL = "https://authserver.mojang.com"
    AUTH_URL = "/authenticate"
    REFRESH_URL = "/refresh"
    VALIDATE_URL = "/validate"
    INVALIDATE_URL = "/invalidate"
    SIGNOUT_URL = "/signout"

    VALID_TIME = 60 * 60
    THROTTLE_TIME = 60
    THROTTLE_COUNT = 20

    username = None
    session_id = None
    display_name = None
    access_token = None
    uuid = None
    user = None
    _last_auth_time = 0
    _waiting_for_join = False
    _waiting_counter = 0

    def __init__(self):
        self.client_token = self._random_token()
        self._join_times = collections.deque()

        session_url = geventhttpclient.url.URL(self.SESSION_URL)
        self._session_http_client = geventhttpclient.HTTPClient.from_url(
            session_url, concurrency=5, ssl_options={
                'ca_certs': certifi.where()
            }
        )

        auth_url = geventhttpclient.url.URL(self.YGGDRASIL_URL)
        self._auth_http_client = geventhttpclient.HTTPClient.from_url(
            auth_url, concurrency=5, ssl_options={
                'ca_certs': certifi.where()
            }
        )

    def get(self):
        return self

    @property
    def session_id(self):
        self.authenticate()
        return "token:%s:%s" % (self.access_token, self.uuid)

    def authenticate(self):
        if self._last_auth_time + self.VALID_TIME < time.time():
            self._authenticate()
            self._last_auth_time = time.time()

    def valid(self):
        try:
            self.authenticate()
        except:
            return False
        else:
            return True

    def joined_server(self):
        self._waiting_for_join = False
        self._waiting_counter = 0

    def join_server(self, server_id, shared_secret, public_key, wait=False):
        if self._waiting_for_join:
            if self._waiting_counter >= self.THROTTLE_COUNT:
                delay = self.THROTTLE_TIME
            else:
                delay = 0.1

            self._waiting_counter += 1
            # TODO: This should be a semaphore, not a delay
            raise AuthenticationThrottledException(delay)

        start_time = time.time()
        if len(self._join_times) >= self.THROTTLE_COUNT:
            if self._join_times[0] >= start_time - self.THROTTLE_TIME:
                raise AuthenticationThrottledException(
                    self.THROTTLE_TIME + self._join_times[0] - start_time
                )
            self._join_times.popleft()
        self._join_times.append(start_time + self.THROTTLE_TIME)

        if wait:
            self._waiting_for_join = True

        try:
            self.authenticate()
            self._session_request(
                self.JOIN_URL,
                {
                    'accessToken': self.access_token,
                    'selectedProfile': self.user,
                    'serverId': self._login_hash(
                        server_id,
                        shared_secret,
                        public_key
                    )
                }
            )
        except AuthenticationException:
            self._waiting_for_join = False
            raise
        finally:
            try:
                self._join_times.remove(start_time + self.THROTTLE_TIME)
            except ValueError:
                # This could potentially happen when there's an issue with the
                # network or Mojang's servers.
                self._join_time.popleft()
            self._join_times.append(time.time())

    @classmethod
    def check_player(cls, username, server_id, shared_secret, public_key):
        """Checks if a user is allowed to join the server."""
        return cls._check_player(username, cls.__login_hash(
            server_id, shared_secret, public_key
        ))

    def _authenticate(self):
        raise NotImplementedError()

    def _auth_request(self, url, data):
        return self._request(self._auth_http_client, url, data)

    def _session_request(self, url, data):
        return self._request(self._session_http_client, url, data)

    def _request(self, client, url, data):
        url = geventhttpclient.url.URL(url)
        r = client.post(url.request_uri, body=json.dumps(data))
        response = json.load(r) if r.content_length else None
        if r.status_code // 100 != 2:
            raise AuthenticationException(response)
        return response

    def __repr__(self):
        return ("Authenticator(user:%s, player:%s)" %
                (self.username, self.display_name))

    @classmethod
    def _random_token(cls):
        return "".join("%02x" % ord(c) for c in
                       encryption.generate_random_bytes(16))

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
    def _check_player(cls, username, session_hash):
        raise NotImplementedError()

    @staticmethod
    def _login_hash(server_id, shared_secret, public_key):
        """Returns the server id which is then used for joining a server"""
        digest = hashlib.sha1()
        digest.update(server_id)
        digest.update(shared_secret)
        digest.update(encryption.encode_public_key(public_key))
        d = long(digest.hexdigest(), 16)
        if d >> 39 * 4 & 0x8:
            return "-%x" % ((-d) & (2 ** (40 * 4) - 1))
        return "%x" % d


class PasswordAuthenticator(Authenticator):
    def __init__(self, username, password):
        super(PasswordAuthenticator, self).__init__()
        self.username = username
        self.password = password

    def _authenticate(self):
        r = self._auth_request(self.AUTH_URL, {
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


class TokenAuthenticator(Authenticator):
    def __init__(self, user=None, profile=None):
        super(TokenAuthenticator, self).__init__()

        config = self._config()

        if user is None and "selectedUser" in config:
            user = config['selectedUser']
        elif user is None:
            if profile is None:
                profile = config['selectedProfile']
            user = config['profiles'][profile]['playerUUID']

        self.user = user
        auth = config['authenticationDatabase'][user]

        self.uuid = auth['uuid']
        self.username = auth['username']
        self.access_token = auth['accessToken']
        self.display_name = auth['displayName']
        self.client_token = config['clientToken']

    def _authenticate(self):
        self._auth_request(self.VALIDATE_URL, {
            'accessToken': self.access_token,
            'clientToken': self.client_token
        })

    @classmethod
    def _config(cls):
        with open(cls._config_path()) as f:
            return json.load(f)

    @classmethod
    def _config_path(cls):
        return os.path.join(cls._minecraft_folder(), "launcher_profiles.json")


class AuthenticationException(Exception):
    def __init__(self, r=None):
        super(AuthenticationException, self).__init__(
            r.get('errorMessage') if isinstance(r, dict) else r
        )
        self.error = r.get('error') if isinstance(r, dict) else None
        self.cause = r.get('cause') if isinstance(r, dict) else None

    def __str__(self):
        error = "%s: %s" % (self.error, self.message)
        if self.cause:
            return "%s (cause: %s)" % (error, self.cause)
        else:
            return error


class AuthenticationThrottledException(AuthenticationException):
    def __init__(self, delay=60):
        super(AuthenticationThrottledException, self).__init__(
            "Authentication throttled",
        )
        self.delay = delay


class AuthenticatorPool(object):
    def __init__(self, *authenticators, **kwargs):
        if authenticators:
            self.authenticators = authenticators
        else:
            self._load_authenticators(**kwargs)
        self._position = 0

    def get(self):
        authenticator = self.authenticators[self._position]
        self._position = (self._position + 1) % len(self.authenticators)
        return authenticator

    def _load_authenticators(self, config=None, config_path=None):
        if not config:
            if config_path:
                with open(config_path) as f:
                    config = json.load(f)
            else:
                config = TokenAuthenticator._config()

        self.authenticators = [
            TokenAuthenticator(user=user)
            for user in config['authenticationDatabase']
        ]
