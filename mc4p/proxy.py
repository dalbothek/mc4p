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

import logging
import logging.config
import re
import signal
import sys
import traceback
import gevent
from time import time, sleep
from optparse import OptionParser
from getpass import getpass
from gevent.server import StreamServer
from gevent.socket import create_connection

import messages
from plugins import PluginConfig, PluginManager
from parsing import parse_unsigned_byte
from util import Stream, PartialPacketException
from authentication import Authenticator, minecraft_credentials
from util import Stream, PartialPacketException, config_logging
import encryption

logger = logging.getLogger("mc4p")
rsa_key = None
auth = None
check_auth = False


def parse_args():
    """Return host and port, or print usage and exit."""
    usage = "usage: %prog [options] host [port]"
    desc = ("Create a Minecraft proxy listening for a client connection," +
            "and forward that connection to <host>:<port>.")
    parser = OptionParser(usage=usage,
                          description=desc)
    parser.add_option("-l", "--log-level", dest="loglvl", metavar="LEVEL",
                      choices=["debug","info","warn","error"],
                      help="Override logging.conf root log level")
    parser.add_option("--log-file", dest='logfile', metavar="FILE", default=None,
                      help="logging configuration file (optional)")
    parser.add_option("-p", "--local-port", dest="locport", metavar="PORT",
                      default="34343", type="int", help="Listen on this port")
    parser.add_option("-c", "--check-authenticity", dest="check_auth",
                      action="store_true", default=False,
                      help="Check authenticity of connecting clients")
    parser.add_option("-a", "--auto-authenticate", dest="authenticate",
                      action="store_true", default=False,
                      help="Authenticate with the credentials stored in the game client")
    parser.add_option("-u", "--user", dest="user", metavar="USERNAME", default=None,
                      help="Authenticate with the given username and ask for the password")
    parser.add_option("-P", "--password-file", dest="password_file",
                      metavar="FILE", default=None,
                      help="Authenticate with the credentials stored in FILE" +
                      "in the form \"username:password\"")
    parser.add_option("--plugin", dest="plugins", metavar="ID:PLUGIN(ARGS)", type="string",
                      action="append", help="Configure a plugin", default=[])
    parser.add_option("--profile", dest="perf_data", metavar="FILE", default=None,
                      help="Enable profiling, save profiling data to FILE")
    (opts,args) = parser.parse_args()

    if not 1 <= len(args) <= 2:
        parser.error("Incorrect number of arguments.") # Calls sys.exit()

    host = args[0]
    port = 25565
    if len(args) > 1:
        try:
            port = int(args[1])
        except ValueError:
            parser.error("Invalid port %s" % args[1])

    pcfg = PluginConfig()
    pregex = re.compile('((?P<id>\\w+):)?(?P<plugin_name>[\\w\\.\\d_]+)(\\((?P<argstr>.*)\\))?$')
    for pstr in opts.plugins:
        m = pregex.match(pstr)
        if not m:
            logger.error('Invalid --plugin option: %s' % pstr)
            sys.exit(1)
        else:
            parts = {'argstr': ''}
            parts.update(m.groupdict())
            pcfg.add(**parts)

    return (host, port, opts, pcfg)


class ServerDispatcher(StreamServer):
    def __init__(self, locport, pcfg, host, port):
        super(ServerDispatcher, self).__init__(("", locport))
        self.pcfg = pcfg
        self.target_host = host
        self.target_port = port
        logger.info("Listening on port %d" % locport)
        if rsa_key is None:
            generate_rsa_key_pair()

    def handle(self, cli_sock, addr):
        logger.info('Incoming connection from %s' % repr(addr))
        try:
            srv_sock = create_connection((self.target_host, self.target_port))
            cli_proxy = MinecraftProxy(cli_sock)
        except Exception as e:
            cli_sock.close()
            logger.error("Couldn't connect to %s:%d - %s", self.target_host,
                         self.target_port, str(e))
            logger.info(traceback.format_exc())
            return
        srv_proxy = MinecraftProxy(srv_sock, cli_proxy)
        plugin_mgr = PluginManager(pcfg, cli_proxy, srv_proxy)
        cli_proxy.plugin_mgr = plugin_mgr
        srv_proxy.plugin_mgr = plugin_mgr
        cli_proxy.start()
        srv_proxy.start()

    def serve_forever(self):
        try:
            super(ServerDispatcher, self).serve_forever()
        except gevent.socket.error, e:
            logger.error(e)

    def close(self):
        self.stop()
        sys.exit()


def generate_rsa_key_pair():
    global rsa_key
    logger.debug('Generating RSA key pair')
    rsa_key = encryption.generate_key_pair()


class UnsupportedPacketException(Exception):
    def __init__(self,pid):
        Exception.__init__(self,"Unsupported packet id 0x%x" % pid)


class EOFException(Exception):
    pass


class MinecraftProxy(gevent.Greenlet):
    """Proxies a packet stream from a Minecraft client or server.
    """

    def __init__(self, src_sock, other_side=None):
        """Proxies one side of a client-server connection.

        MinecraftProxy instances are created in pairs that have references to
        one another. Since a client initiates a connection, the client side of
        the pair is always created first, with other_side = None. The creator
        of the client proxy is then responsible for connecting to the server
        and creating a server proxy with other_side=client. Finally, the
        proxy creator should do client_proxy.other_side = server_proxy.
        """
        super(MinecraftProxy, self).__init__()

        self.sock = src_sock
        self.closed = False
        self.plugin_mgr = None
        self.other_side = other_side
        self.rsa_key = None
        self.shared_secret = None
        self.challenge_token = None
        self.send_cipher = None
        self.recv_cipher = None
        if other_side == None:
            self.side = 'client'
            self.msg_spec = messages.protocol[0][0]
            self.rsa_key = rsa_key
            self.username = None
        else:
            self.side = 'server'
            self.msg_spec = messages.protocol[0][1]
            self.other_side.other_side = self
            self.shared_secret = encryption.generate_shared_secret()
        self.stream = Stream()
        self.last_report = 0
        self.msg_queue = []
        self.out_of_sync = False

    def handle_read(self):
        """Read all available bytes, and process as many packets as possible.
        """
        t = time()
        if self.last_report + 5 < t and self.stream.tot_bytes > 0:
            self.last_report = t
            logger.debug("%s: total/wasted bytes is %d/%d (%f wasted)" % (
                 self.side, self.stream.tot_bytes, self.stream.wasted_bytes,
                 100 * float(self.stream.wasted_bytes) / self.stream.tot_bytes))
        self.stream.append(self.recv(4092))

        if self.out_of_sync:
            data = self.stream.read(len(self.stream))
            self.stream.packet_finished()
            if self.other_side:
                self.other_side.send(data)
            return

        try:
            packet = parse_packet(self.stream, self.msg_spec, self.side)
            while packet != None:
                rebuild = False
                if packet['msgtype'] == 0x02 and self.side == 'client':
                    # Determine which protocol message definitions to use.
                    proto_version = packet['proto_version']
                    logger.info('Client requests protocol version %d' % proto_version)
                    if not proto_version in messages.protocol:
                        logger.error("Unsupported protocol version %d" % proto_version)
                        self.handle_close()
                        return
                    self.username = packet['username']
                    self.msg_spec, self.other_side.msg_spec = messages.protocol[proto_version]
                    self.cipher = encryption.encryption_for_version(proto_version)
                    self.other_side.cipher = self.cipher
                elif packet['msgtype'] == 0xfd:
                    self.rsa_key = encryption.decode_public_key(
                        packet['public_key']
                    )
                    self.encoded_rsa_key = packet['public_key']
                    packet['public_key'] = encryption.encode_public_key(
                        self.other_side.rsa_key
                    )
                    if 'challenge_token' in packet:
                        self.challenge_token = packet['challenge_token']
                        self.other_side.challenge_token = self.challenge_token
                    self.other_side.server_id = packet['server_id']
                    if check_auth:
                        packet['server_id'] = encryption.generate_server_id()
                    else:
                        packet['server_id'] = "-"
                    self.server_id = packet['server_id']
                    rebuild = True
                elif packet['msgtype'] == 0xfc and self.side == 'client':
                    self.shared_secret = encryption.decrypt_shared_secret(
                        packet['shared_secret'],
                        self.rsa_key
                    )
                    if (len(self.shared_secret) > 16 and
                        self.cipher == encryption.RC4):
                        logger.error("Unsupported protocol version")
                        self.handle_close()
                        return
                    packet['shared_secret'] = encryption.encrypt_shared_secret(
                        self.other_side.shared_secret,
                        self.other_side.rsa_key
                    )
                    if 'challenge_token' in packet:
                        challenge_token = encryption.decrypt_shared_secret(
                            packet['challenge_token'], self.rsa_key
                        )
                        if challenge_token != self.challenge_token:
                            self.kick("Invalid client reply")
                            return
                        packet['challenge_token'] = encryption.encrypt_shared_secret(
                            self.other_side.challenge_token,
                            self.other_side.rsa_key
                        )
                    if auth:
                        logger.info("Authenticating on server")
                        auth.join_server(self.server_id,
                                        self.other_side.shared_secret,
                                        self.other_side.rsa_key)
                    if check_auth:
                        logger.info("Checking authenticity")
                        if not Authenticator.check_player(
                            self.username, self.other_side.server_id,
                            self.shared_secret, self.rsa_key):
                            self.kick("Unable to verify username")
                            return
                    rebuild = True
                elif packet['msgtype'] == 0xfc and self.side == 'server':
                    logger.debug("Starting encryption")
                    self.start_cipher()
                forward = True
                if self.plugin_mgr:
                    forwarding = self.plugin_mgr.filter(packet, self.side)
                    if forwarding and packet.modified:
                        rebuild = True
                if rebuild:
                    packet['raw_bytes'] = self.msg_spec[packet['msgtype']].emit(packet)
                if forwarding and self.other_side is not None:
                    self.other_side.send(packet['raw_bytes'])
                if packet['msgtype'] == 0xfc and self.side == 'server':
                    self.other_side.start_cipher()
                # Since we know we're at a message boundary, we can inject
                # any messages in the queue.
                msgbytes = self.plugin_mgr.next_injected_msg_from(self.side)
                while self.other_side and msgbytes is not None:
                    self.other_side.send(msgbytes)
                    msgbytes = self.plugin_mgr.next_injected_msg_from(self.side)

                # Attempt to parse the next packet.
                packet = parse_packet(self.stream,self.msg_spec, self.side)
        except PartialPacketException:
            pass # Not all data for the current packet is available.
        except Exception:
            logger.error("MinecraftProxy for %s caught exception, out of sync" % self.side)
            logger.error(traceback.format_exc())
            logger.debug("Current stream buffer: %s" % repr(self.stream.buf))
            self.out_of_sync = True
            self.stream.reset()

    def kick(self, reason):
        self.send(self.msg_spec[0xff].emit({'reason': reason}))
        self.handle_close()

    def handle_close(self):
        """Call shutdown handler."""
        logger.info("%s socket closed.", self.side)
        self.close()
        if self.other_side is not None:
            logger.info("shutting down other side")
            self.other_side.other_side = None
            self.other_side.close()
            self.other_side = None
            logger.info("shutting down plugin manager")
            self.plugin_mgr.destroy()

    def start_cipher(self):
        self.recv_cipher = self.cipher(self.shared_secret)
        self.send_cipher = self.cipher(self.shared_secret)

    def recv(self, buffer_size):
        data = self.sock.recv(buffer_size)
        if not data:
            raise EOFException()
        if self.recv_cipher is None:
            return data
        return self.recv_cipher.decrypt(data)

    def send(self, data):
        if self.send_cipher is not None:
            data = self.send_cipher.encrypt(data)
        return self.sock.sendall(data)

    def close(self):
        self.closed = True
        self.sock.close()

    def _run(self):
        while not self.closed:
            try:
                self.handle_read()
            except EOFException:
                break
            gevent.sleep()
        self.close()
        self.handle_close()

class Message(dict):
    def __init__(self, d):
        super(Message, self).__init__(d)
        self.modified = False

    def __setitem__(self, key, val):
        if key in self and self[key] != val:
            self.modified = True
        return super(Message, self).__setitem__(key, val)

def parse_packet(stream, msg_spec, side):
    """Parse a single packet out of stream, and return it."""
    # read Packet ID
    msgtype = parse_unsigned_byte(stream)
    if not msg_spec[msgtype]:
        raise UnsupportedPacketException(msgtype)
    logger.debug("%s trying to parse message type %x" % (side, msgtype))
    msg_parser = msg_spec[msgtype]
    msg = msg_parser.parse(stream)
    msg['raw_bytes'] = stream.packet_finished()
    return Message(msg)


if __name__ == "__main__":
    logging.basicConfig(level=logging.ERROR)
    (host, port, opts, pcfg) = parse_args()

    if opts.logfile:
        config_logging(opts.logfile)

    if opts.loglvl:
        logging.root.setLevel(getattr(logging, opts.loglvl.upper()))

    if opts.user:
        while True:
            password = getpass("Minecraft account password: ")
            auth = Authenticator(opts.user, password)
            logger.debug("Authenticating with %s" % opts.user)
            if auth.check():
                break
            logger.error("Authentication failed")
        logger.debug("Credentials are valid")

    if opts.authenticate or opts.password_file:
        if opts.authenticate:
            credentials = minecraft_credentials()
            if credentials is None:
                logger.error("Can't find password file. " +
                             "Use --user or --password-file option instead.")
                sys.exit(1)
            user, password = credentials
        else:
            try:
                with open(opts.password_file) as f:
                    credentials = f.read().strip()
            except IOError as e:
                logger.error("Can't read password file: %s" % e)
                sys.exit(1)
            if ':' not in credentials:
                logger.error("Invalid password file")
                sys.exit(1)
            user = credentials[:credentials.find(':')]
            password = credentials[len(user)+1:]
        auth = Authenticator(user, password)
        logger.debug("Authenticating with %s" % user)
        if not auth.check():
            logger.error("Authentication failed")
            sys.exit(1)
        logger.debug("Credentials are valid")

    if opts.check_auth:
        check_auth = True

    server = ServerDispatcher(opts.locport, pcfg, host, port)

    # Install signal handler.
    gevent.signal(signal.SIGTERM, server.close)
    gevent.signal(signal.SIGINT, server.close)

    # I/O event loop.
    if opts.perf_data:
        logger.warn("Profiling enabled, saving data to %s" % opts.perf_data)
        import cProfile
        cProfile.run('server.serve_forever()', opts.perf_data)
    else:
        server.serve_forever()

