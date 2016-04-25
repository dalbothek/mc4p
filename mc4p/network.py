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

import traceback
import logging
import time
import sys

import gevent.server
import gevent.socket
from gevent import event

from mc4p import stream
from mc4p import protocol
from mc4p import parsing
from mc4p import util
from mc4p import encryption
from mc4p import authentication
from mc4p import dns


logger = logging.getLogger("network")

REFERENCE_PROTOCOL = protocol.get_latest_protocol()
CLIENT_PROTOCOL = REFERENCE_PROTOCOL.client_bound
SERVER_PROTOCOL = REFERENCE_PROTOCOL.server_bound


class _MetaEndpoint(type):
    def __init__(cls, name, bases, nmspc):
        super(_MetaEndpoint, cls).__init__(name, bases, nmspc)

        if hasattr(cls, "class_packet_handlers"):
            handlers = cls._copy_packet_handlers(cls.class_packet_handlers)
        else:
            handlers = {}

        for f in cls.__dict__.itervalues():
            if callable(f) and hasattr(f, "_handled_packets"):
                while f._handled_packets:
                    key = cls._packet_handler_key(f._handled_packets.pop())
                    handlers.setdefault(key, []).append(f)

        cls.class_packet_handlers = handlers

    def packet_handler(cls, packet):
        def packet_handler_wrapper(f):
            if not hasattr(f, "_handled_packets"):
                f._handled_packets = []
            f._handled_packets.append(packet)
            return f

        return packet_handler_wrapper


class Endpoint(gevent.Greenlet):
    __metaclass__ = _MetaEndpoint

    def __init__(self, sock, incoming_direction, version=0):
        super(Endpoint, self).__init__()
        self.sock = sock

        self.packet_handler = self._instance_packet_handler

        self.input_direction = incoming_direction
        self.input_stream = stream.BufferedPacketInputStream(
            self.input_direction, version
        )

        self.output_direction = protocol.Direction.opposite_direction(
            incoming_direction
        )
        self.output_stream = stream.PacketOutputStream(
            self.output_direction, version
        )

        self.input_stream.pair(self.output_stream)
        self.instance_packet_handlers = self._copy_packet_handlers(
            self.class_packet_handlers, bind_to=self
        )

        self.disconnect_handlers = []
        self._disconnect_reason = None
        self._disconnect_exception = None
        self._last_packet_sent = None
        self._last_packet_received = None
        self.connected = True
        self.init()

    @classmethod
    def _copy_packet_handlers(cls, handlers, bind_to=None):
        return dict(
            (k, [
                f.__get__(bind_to, cls) if bind_to is not None else f
                for f in v
            ]) for k, v in handlers.iteritems()
        )

    @property
    def input_protocol(self):
        return self.input_stream.protocol.directions[self.input_direction]

    @property
    def output_protocol(self):
        return self.output_stream.protocol.directions[self.output_direction]

    def init(self):
        pass

    def _handle_disconnect(self):
        for handler in self.disconnect_handlers:
            handler()
        self.handle_disconnect()

    def handle_disconnect(self):
        pass

    def disconnect_handler(self, f):
        self.register_disconnect_handler(f)
        return f

    def register_disconnect_handler(self, f):
        self.disconnect_handlers.append(f)

    def unregister_disconnect_handler(self, f):
        self.disconnect_handlers.remove(f)

    def handle_packet(self, packet):
        return False

    def _call_packet_handlers(self, packet):
        key = self._packet_handler_key(packet)
        handlers = self.instance_packet_handlers.get(key)
        if handlers:
            # handlers might unregister themselves, so we need to copy the list
            for handler in tuple(handlers):
                if handler(packet):
                    return True

    def _instance_packet_handler(self, packet):
        def packet_handler_wrapper(f):
            self.register_packet_handler(packet, f)
            return f
        return packet_handler_wrapper

    def register_packet_handler(self, packet, f):
        key = self._packet_handler_key(packet)
        self.instance_packet_handlers.setdefault(key, []).append(f)

    def unregister_packet_handler(self, packet, f):
        key = self._packet_handler_key(packet)
        self.instance_packet_handlers[key].remove(f)

    def wait_for_packet(self, packets, timeout=None):
        result = event.AsyncResult()

        if not hasattr(packets, "__iter__"):
            packets = (packets,)

        @self.disconnect_handler
        def async_result_packet_handler(packet_=None):
            if packet_:
                result.set(packet_)
            else:
                if self._disconnect_reason == "Failed to verify username!":
                    exc = authentication.AuthenticationException(
                        self._disconnect_reason
                    )
                else:
                    exc = DisconnectException(self._disconnect_reason)
                result.set_exception(exc)

        for packet in packets:
            self.register_packet_handler(packet, async_result_packet_handler)

        try:
            return result.get(timeout=timeout)
        except gevent.Timeout:
            return None
        finally:
            self.unregister_disconnect_handler(async_result_packet_handler)
            for packet in packets:
                self.unregister_packet_handler(packet,
                                               async_result_packet_handler)

    def wait_for_multiple(self, packets, timeout=None, max_delay=0.2):
        packets_received = []

        while True:
            packet = self.wait_for_packet(
                packets, timeout=max_delay if packets_received else timeout
            )
            if packet:
                packets_received.append(packet)
            else:
                break

        return packets_received

    def wait_for_world_load(self):
        packets = [self.input_protocol.play.ChunkData]
        if hasattr(self.input_protocol.play, "MapChunkBulk"):
            packets.append(self.input_protocol.play.MapChunkBulk)

        self.wait_for_multiple(packets, timeout=1)

    @staticmethod
    def _packet_handler_key(packet):
        return (packet._state, packet._name)

    def handle_packet_error(self, error):
        return False

    def close(self):
        if self.connected:
            if self._disconnect_reason is None:
                self._disconnect_reason = "Connection was closed from this end"
            self.connected = False
            self.sock.close()
            self._handle_disconnect()

    def send(self, packet):
        #packet._show()
        self._last_packet_sent = packet
        data = self.output_stream.emit(packet)
        if isinstance(data, util.CombinedMemoryView):
            for part in data.data_parts:
                self.sock.sendall(part)
        else:
            self.sock.sendall(data)

    def _run(self):
        while self.connected:
            try:
                self._recv()
            except EOFError:
                self._disconnect_reason = "The connection was closed"
                break
            except Exception as e:
                if not isinstance(e, gevent.socket.error) or e.errno != 9:
                    self._disconnect_reason = e.message
                    self._disconnect_exception = e
                    self._disconnect_traceback = traceback.format_exc()
                break
            gevent.sleep()
        self.close()

    def _recv(self):
        read_bytes = self.sock.recv_into(self.input_stream.write_buffer())
        if not read_bytes:
            raise EOFError()
        self.input_stream.added_bytes(read_bytes)
        try:
            for packet in self.input_stream.read_packets():
                #packet._show()
                self._last_packet_received = packet
                if not self.handle_packet(packet):
                    self._call_packet_handlers(packet)
                gevent.sleep()
        except Exception as e:
            if not self.handle_packet_error(e):
                raise


class DisconnectException(Exception):
    def __init__(self, message=None):
        if isinstance(message, unicode):
            message = message.encode("utf8")

        super(DisconnectException, self).__init__(message)


class ClientHandler(Endpoint):
    def __init__(self, sock, addr, server, version=0):
        self.addr = addr
        self.server = server
        super(ClientHandler, self).__init__(
            sock, protocol.Direction.server_bound, version
        )


class Server(gevent.server.StreamServer):
    def __init__(self, addr, handler=ClientHandler):
        super(Server, self).__init__(addr)
        self.handler = handler
        logger.info("Listening on %s:%d" % addr)

    def handle(self, sock, addr):
        logger.info("Incoming connection from %s:%d" % addr)
        handler = self.handler(sock, addr, self)
        handler.start()

    def run(self):
        try:
            super(Server, self).serve_forever()
        except gevent.socket.error, e:
            logger.error(e)


class Client(Endpoint):
    def __init__(self, addr, version=None, logfile=None):
        if version is None:
            version = protocol.MAX_PROTOCOL_VERSION

        self._log_file = logfile
        if isinstance(logfile, basestring):
            self._log_file = open(logfile, "a")

        self._start_time = time.time()
        self.log("Start time: %s" % time.strftime("%X"))

        self.log("Resolving hostname")
        self.original_addr = addr
        self.addr = dns.resolve(*addr)

        if self.addr is None:
            raise Exception("Could not resolve hostname")

        self.log("Connecting")
        sock = gevent.socket.create_connection(self.addr)
        self.log("Connected")

        super(Client, self).__init__(
            sock, protocol.Direction.client_bound, version
        )

        self.authenticator = None
        self._waiting_for_join = False
        self._spawned = False

    def log(self, *message):
        if self._log_file is not None:
            message = "%.2f - %s\n" % (time.time() - self._start_time,
                                       " ".join(map(unicode, message)))
            try:
                self._log_file.write(message.encode("utf8"))
            except IOError as e:
                print("Error while writing log message: %s (message: %s)" %
                      (e, message), file=sys.stdout)

    def handle_disconnect(self):
        self.log("Disconnect: %s" % self._disconnect_reason)
        if self._waiting_for_join:
            self.authenticator.joined_server()
        try:
            self._log_file.close()
        except:
            pass

    def handle_packet(self, packet):
        self.log("<-", packet)

    def send(self, packet):
        self.log("->", packet)
        super(Client, self).send(packet)

    def wait_for_packet(self, packets, timeout=60):
        self.log("Waiting for %s" % packets)
        return super(Client, self).wait_for_packet(packets, timeout)

    def send_handshake(self, next_state=protocol.State.login):
        self.send(self.output_protocol.handshake.Handshake(
            version=self.output_protocol.protocol.version,
            host=self.original_addr[0],
            port=self.original_addr[1],
            state=protocol.State.index(next_state)
        ))

    def login(self, authenticator=None):
        if authenticator is None:
            authenticator = authentication.TokenAuthenticator()
        self.authenticator = authenticator.get()

        self.send_handshake()
        self.send(self.output_protocol.login.LoginStart(
            name=self.authenticator.display_name
        ))

    @Endpoint.packet_handler(CLIENT_PROTOCOL.login.EncryptionRequest)
    def handle_encryption_key_request(self, packet):
        public_key = encryption.decode_public_key(packet.public_key.tobytes())
        self.shared_secret = encryption.generate_shared_secret()

        if self.authenticator is not None:
            for i in range(1000):
                try:
                    self.authenticator.join_server(
                        packet.server_id, self.shared_secret, public_key,
                        wait=True
                    )
                except authentication.AuthenticationThrottledException as e:
                    logger.debug("Waiting %s seconds before authenticating" %
                                 e.delay)
                    gevent.sleep(e.delay)
                    continue
                break
            else:
                raise e
            self._waiting_for_join = True

        self.input_stream.enable_encryption(self.shared_secret)
        self.send(self.output_protocol.login.EncryptionResponse(
            shared_secret=encryption.encrypt_shared_secret(
                self.shared_secret, public_key
            ),
            verify_token=encryption.encrypt_shared_secret(
                packet.verify_token.tobytes(), public_key
            ),
        ))
        self.output_stream.enable_encryption(self.shared_secret)

    @Endpoint.packet_handler(CLIENT_PROTOCOL.login.LoginSuccess)
    def handle_login_success(self, packet):
        if self._waiting_for_join:
            self._waiting_for_join = False
            self.authenticator.joined_server()

    @Endpoint.packet_handler(CLIENT_PROTOCOL.login.Disconnect)
    @Endpoint.packet_handler(CLIENT_PROTOCOL.play.Disconnect)
    def handle_disconnect_packet(self, packet):
        self._disconnect_reason = util.parse_chat(packet.reason)
        self.close()

    @Endpoint.packet_handler(CLIENT_PROTOCOL.play.PlayerAbilities)
    def handle_player_abilities(self, packet):
        self.send(self.output_protocol.play.PluginMessage(
            channel="MC|Brand",
            data=parsing.String.emit("mc4p")
        ))

    @Endpoint.packet_handler(CLIENT_PROTOCOL.play.PlayerPositionAndLook)
    def handle_player_position_and_look(self, packet):
        if not self._spawned:
            self.send(self.output_protocol.play.PlayerPositionAndLook(
                _ignore_extra_fields=True,
                x=packet.x,
                feet_y=packet.y + 1.62,
                y=packet.y,
                z=packet.z,
                yaw=packet.yaw,
                pitch=packet.pitch,
                on_ground=True
            ))

            self.send(self.output_protocol.play.ClientStatus(
                action_id=0
            ))

            self._spawned = True

    @Endpoint.packet_handler(CLIENT_PROTOCOL.play.KeepAlive)
    def handle_keep_alive(self, packet):
        self.send(self.output_protocol.play.KeepAlive(
            keep_alive_id=packet.keep_alive_id
        ))
