# This source file is part of mc3p, the Minecraft Protocol Parsing Proxy.
#
# This program is free software. It comes without any warranty, to
# the extent permitted by applicable law. You can redistribute it
# and/or modify it under the terms of the Do What The Fuck You Want
# To Public License, Version 2, as published by Sam Hocevar. See
# http://sam.zoy.org/wtfpl/COPYING for more details

import socket
import sys
from struct import pack, unpack
from optparse import OptionParser
from contextlib import closing
from random import choice
from zlib import compress, decompress

import encryption
from messages import protocol
from parsing import parse_unsigned_byte
from authentication import Authenticator
from proxy import UnsupportedPacketException


class MockTerminal(object):
    class ColorTag(str):
        def __call__(self, string):
            return string

        def __str__(self):
            return ""

    def __getattr__(self, name):
        return self.ColorTag()


output_width = 79
if sys.platform == "win32":
    is_terminal = False
    t = MockTerminal()
else:
    from blessings import Terminal
    t = Terminal()
    is_terminal = t.is_a_tty
    if is_terminal:
        output_width = max(t.width, output_width)


def parse_args():
    """Return options, or print usage and exit."""
    usage = "Usage: %prog [options] [port]"
    desc = ("Create a Minecraft server listening for a client connection.")
    parser = OptionParser(usage=usage, description=desc)
    parser.add_option("-c", "--send-chunks", dest="send_chunks",
                      action="store_true", default=False,
                      help="send some more packets after the encrypted " +
                           "connection was established")
    parser.add_option("-s", "--stay-connected", dest="stay_connected",
                      action="store_true", default=False,
                      help="don't disconnect after a successfull handshake")
    (opts, args) = parser.parse_args()

    if not 0 <= len(args) <= 1:
        parser.error("Incorrect number of arguments.")

    port = 25565
    if len(args) > 0:
        try:
            port = int(args[0])
        except ValueError:
            parser.error("Invalid port %s" % args[0])

    return (port, opts)


class LoggingSocketStream(object):
    def __init__(self, sock):
        self.sock = sock

    def __enter__(self):
        sys.stdout.write(t.bold("Receiving raw bytes: "))

    def read(self, length):
        data = ""
        for i in range(length):
            data += self._read_byte()
        sys.stdout.write(" ")
        return data

    def _read_byte(self):
        byte = self.sock.recv(1)
        if byte == '':
            raise EOFException()
        sys.stdout.write("%02x " % ord(byte))
        return byte

    def __exit__(self, exception_type, exception_value, traceback):
        sys.stdout.write("\n")


class LoggingSocketCipherStream(LoggingSocketStream):
    def __init__(self, sock, cipher):
        self.sock = sock
        self.cipher = cipher
        self.data = []
        self.pos = 21

    def __enter__(self):
        if is_terminal:
            sys.stdout.write(t.bold("Receiving raw bytes: ") + t.move_down)
            sys.stdout.write(t.bold("Decrypted bytes:     ") + t.move_up)
        else:
            sys.stdout.write("Receiving raw bytes: ")

    def read(self, length):
        data = super(LoggingSocketCipherStream, self).read(length)
        self.pos += 1
        self.data.append(data)
        return data

    def _read_byte(self):
        byte = super(LoggingSocketCipherStream, self)._read_byte()
        decrypted = self.cipher.decrypt(byte)
        if is_terminal:
            sys.stdout.write(''.join((t.move_down, t.move_right * self.pos,
                                      "%02x " % ord(decrypted), t.move_up)))
        self.pos += 3
        return decrypted

    def __exit__(self, exception_type, exception_value, traceback):
        if is_terminal:
            sys.stdout.write(t.move_down * 2)
        else:
            sys.stdout.write("\n")
            sys.stdout.write("Decrypted bytes:     ")
            print "  ".join(
                " ".join("%02x" % ord(c) for c in field) for field in self.data
            )


class PacketFormatter(object):
    IGNORE = ('msgtype', 'raw_bytes')

    @classmethod
    def print_packet(cls, packet):
        formatter = "_format_packet_%02x" % packet['msgtype']
        substitutes = {}
        lengths = [len(field) for field in packet if field not in cls.IGNORE]
        if not lengths:
            return
        maxlen = max(lengths)
        if hasattr(cls, formatter):
            substitutes = getattr(cls, formatter)(packet, maxlen + 4)
        print t.bold("Packet content:")
        for field in packet:
            if field in cls.IGNORE:
                continue
            if field in substitutes:
                value = substitutes[field]
                if value is None:
                    continue
                if isinstance(value, tuple) or isinstance(value, list):
                    value = cls._multi_line(value, maxlen + 4)
            else:
                value = packet[field]
            print "  %s:%s %s" % (field, " " * (maxlen - len(field)), value)

    @classmethod
    def bytes(cls, bytes, prefix="", prefix_format=None):
        prefix_length = len(prefix)
        if prefix_format is not None:
            prefix = prefix_format(prefix)
        return cls._multi_line(cls._bytes(bytes, prefix, 0, prefix_length), 0)

    @classmethod
    def _format_packet_fd(cls, packet, prelen):
        key = encryption.decode_public_key(packet['public_key'])
        modulus = cls._split_lines("%x" % key.key.n, "modulus:  0x", prelen)
        token = ' '.join("%02x" % ord(c) for c in packet['challenge_token'])
        raw = cls._bytes(packet['public_key'], "raw:      ", prelen)
        return {'challenge_token': token,
                'public_key': ["exponent: 0x%x" % key.key.e] + modulus + raw}

    @classmethod
    def _format_packet_38(cls, packet, prelen):
        data = cls._bytes(packet['chunks']['data'], "data: ", prelen)
        meta = cls._table(packet['chunks']['metadata'], "meta: ", prelen)
        return {'chunks': data + meta}

    @classmethod
    def _format_packet_fc(cls, packet, prelen):
        token = cls._bytes(packet['challenge_token'], prelen=prelen)
        secret = cls._bytes(packet['shared_secret'], prelen=prelen)
        return {'challenge_token': token,
                'shared_secret': secret}

    @staticmethod
    def _table(items, prefix, prelen=0):
        if not items:
            return [prefix + "Empty"]
        titles = items[0].keys()
        maxlen = [len(title) for title in titles]
        for i in range(len(titles)):
            title = titles[i]
            for item in items:
                if len(str(item[title])) > maxlen[i]:
                    maxlen[i] = len(str(item[title]))

        def row(values, title=False):
            if title:
                line = prefix
            else:
                line = " " * len(prefix)
            for i in range(len(values)):
                value = values[i]
                l = maxlen[i]
                if isinstance(value, str):
                    line += value + " " * (l - len(value) + 1)
                else:
                    line += " " * (l - len(str(value))) + str(value) + " "
            return line

        def separator():
            return " " * len(prefix) + "-".join("-" * l for l in maxlen)

        lines = [row(titles, title=True), separator()]
        for item in items:
            lines.append(row([item[title] for title in titles]))
        return lines

    @classmethod
    def _bytes(cls, bytes, prefix="", prelen=0, prefix_length=None):
        return cls._split_lines(" ".join("%02x" % ord(c) for c in bytes),
                                prefix=prefix, prelen=prelen,
                                prefix_length=prefix_length, partlen=3)

    @staticmethod
    def _split_lines(text, prefix="", prelen=0, prefix_length=None, partlen=1):
        lines = []
        prefix_length = prefix_length or len(prefix)
        length = output_width - prelen - prefix_length
        length = length - length % partlen
        for i in range(0, len(text), length):
            line = prefix if i == 0 else " " * prefix_length
            line += text[i:min(i + length, len(text))]
            lines.append(line)
        return lines

    @staticmethod
    def _multi_line(lines, offset):
        return ("\n" + " " * offset).join(lines)


class Server(object):
    def __init__(self, port, send_chunks=False, stay_connected=False):
        self.port = port
        self.send_chunks = send_chunks
        self.stay_connected = stay_connected

    def start(self):
        with closing(socket.socket(socket.AF_INET,
                                   socket.SOCK_STREAM)) as srvsock:
            srvsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srvsock.bind(("", self.port))
            srvsock.listen(1)
            print t.bold("Listening on port %s" % self.port)
            while True:
                try:
                    self._handle_client(srvsock.accept())
                except UnexpectedPacketException, e:
                    print t.bold_red("\nError:"),
                    print "Received unexpected 0x%02x packet" % (e.id_)
                    if e.encrypted_id is not None:
                        print t.bold("\nExpected message id (encrypted):"),
                        print "%02x" % e.encrypted_id
                except UnsupportedPacketException, e:
                    print t.bold_red("\nError:"),
                    print "Received unsupported 0x%02x packet" % (e.id_)
                except EOFException:
                    print t.bold_red("\nError:"),
                    print "Socket closed by client"
                print t.bold("\nConnection closed")

    def _handle_client(self, connection):
        with closing(connection[0]) as sock:
            clt_spec, srv_spec = protocol[0]
            print t.bold("\nConnected to %s:%s" % connection[1])

            print t.bold_cyan("\nExpecting Server Ping (0xfe) " +
                              "or Handshake (0x02) packet")
            packet = parse_packet(sock, clt_spec)
            if packet['msgtype'] == 0xfe:
                send_packet(sock, srv_spec, {'msgtype': 0xff,
                                             'reason': 'mc3p debugger'})
                return
            elif packet['msgtype'] != 0x02:
                raise UnexpectedPacketException(packet['msgtype'])
            if packet['proto_version'] < 38:
                print t.bold_red("Error:"),
                print "Unsupported protocol version"
                return
            username = packet['username']
            clt_spec, srv_spec = protocol[packet['proto_version']]

            print t.bold("\nGenerating RSA key pair")
            key = encryption.generate_key_pair()
            challenge = encryption.generate_challenge_token()
            server_id = encryption.generate_server_id()

            packet = {'msgtype': 0xfd,
                      'server_id': server_id,
                      'public_key': encryption.encode_public_key(key),
                      'challenge_token': challenge}
            send_packet(sock, srv_spec, packet)

            packet = parse_packet(sock, clt_spec, 0xfc)
            try:
                decrypted_token = encryption.decrypt_shared_secret(
                    packet['challenge_token'], key
                )
            except:
                decrypted_token = None
            if decrypted_token is None:
                try:
                    decrypted_token = key.decrypt(packet['challenge_token'])
                except:
                    pass
                if decrypted_token == challenge:
                    print t.bold_red("\nError:"),
                    print ("The challenge token was not padded " +
                           "correctly. See ftp://ftp.rsasecurity.com/pub/" +
                           "pkcs/pkcs-1/pkcs-1v2-1.pdf section 7.2.1 if " +
                           "your library does not support PKCS#1 padding.")
                else:
                    print t.bold_red("\nError:"),
                    print "The challenge token is not encrypted correctly.\n"
                    print PacketFormatter.bytes(decrypted_token,
                                                "Decrypted bytes: ", t.bold)
                return
            elif decrypted_token != challenge:
                print t.bold_red("\nError:"),
                print "Received challenge token does not",
                print "match the expected value.\n"
                print PacketFormatter.bytes(decrypted_token,
                                            "Received bytes: ", t.bold)
                print
                print PacketFormatter.bytes(challenge,
                                            "Expected bytes: ", t.bold)
                return
            secret = encryption.decrypt_shared_secret(packet['shared_secret'],
                                                      key)
            if secret is None:
                print t.bold_red("\nError:"),
                print ("The shared secret was not padded" +
                       "correctly. See ftp://ftp.rsasecurity.com/pub/" +
                       "pkcs/pkcs-1/pkcs-1v2-1.pdf section 7.2.1 if " +
                       "your library does not support PKCS#1 padding.")
                return
            print PacketFormatter.bytes(secret, "Shared secret: ", t.bold)
            if len(secret) != 16:
                print t.bold_red("\nError:"),
                print "The shared secret must be 16 bytes long",
                print "(received length is %s)" % len(secret)
                return

            print t.bold_cyan("\nAuthentication")
            print PacketFormatter.bytes(server_id, "Server ID:     ", t.bold)
            print PacketFormatter.bytes(secret, "Shared secret: ", t.bold)
            print PacketFormatter.bytes(encryption.encode_public_key(key),
                                        "Public key:    ", t.bold)
            print t.bold("Login hash:   "),
            print Authenticator.login_hash(server_id, secret, key)
            if Authenticator.check_player(username, server_id, secret, key):
                print t.bold_green("Success:"), "You are authenticated"
            else:
                print t.bold_yellow("Warning:"), "You are not authenticated"

            send_packet(sock, srv_spec, {'msgtype': 0xfc,
                                         'challenge_token': '',
                                         'shared_secret': ''})

            print t.bold("\nStarting AES encryption")
            clt_cipher = encryption.AES128CFB8(secret)
            srv_cipher = encryption.AES128CFB8(secret)
            backup_cipher = encryption.AES128CFB8(secret)

            parse_packet(sock, clt_spec, 0xcd, clt_cipher, backup_cipher)

            send_packet(sock, srv_spec, {'msgtype': 0x01,
                                         'eid': 1337,
                                         'level_type': 'flat',
                                         'server_mode': 0,
                                         'dimension': 0,
                                         'difficulty': 2,
                                         'unused': 0,
                                         'max_players': 20}, srv_cipher)

            if self.send_chunks:
                while True:
                    print
                    packet = parse_packet(sock, clt_spec, cipher=clt_cipher)
                    if packet['msgtype'] == 0x0d:
                        break

                x, y, z = 5, 9, 5

                send_packet(sock, srv_spec, {'msgtype': 0x06,
                                             'x': x,
                                             'y': y,
                                             'z': z}, srv_cipher)

                send_packet(sock, srv_spec, {'msgtype': 0xca,
                                             'abilities': 0b0100,
                                             'walking_speed': 25,
                                             'flying_speed': 12}, srv_cipher)

                send_packet(sock, srv_spec, {'msgtype': 0x04,
                                             'time': 0}, srv_cipher)

                send_packet(sock, srv_spec, multi_chunk_packet(), srv_cipher)

                send_packet(sock, srv_spec, {'msgtype': 0x0d,
                                             'x': x,
                                             'y': y,
                                             'stance': y + 1.5,
                                             'z': z,
                                             'yaw': 0,
                                             'pitch': 0,
                                             'on_ground': False}, srv_cipher)

                buffer = StringSocket()

                send_packet(buffer, srv_spec,
                            {'msgtype': 0x03,
                             'chat_msg': 'First message'},
                            srv_cipher)

                send_packet(buffer, srv_spec,
                            {'msgtype': 0x03,
                             'chat_msg': 'Second message'}, srv_cipher)

                sock.sendall(buffer.data)

            if self.stay_connected:
                while True:
                    packet = parse_packet(sock, clt_spec, cipher=clt_cipher,
                                          title=True)
                    if packet['msgtype'] == 0xff:
                        break
                    elif packet['msgtype'] == 0x00:
                        send_packet(buffer, srv_spec, {'msgtype': 0x00,
                                                       'id': 0}, srv_cipher)
                        break
            else:
                send_packet(sock, srv_spec,
                            {'msgtype': 0xff,
                             'reason': "Successfully logged in"}, srv_cipher)


def parse_packet(sock, msg_spec, expecting=None,
                 cipher=None, backup_cipher=None, title=False):
    if expecting is not None:
        packet = msg_spec[expecting]
        print t.bold_cyan("\nExpecting %s (0x%02x) packet" % (packet.name,
                                                              expecting))
    if title and is_terminal:
        sys.stdout.write(t.move_down * 2)
    elif title:
        print

    if cipher is None:
        stream = LoggingSocketStream(sock)
    else:
        stream = LoggingSocketCipherStream(sock, cipher)
    with stream:
        msgtype = parse_unsigned_byte(stream)
        if expecting is not None and msgtype != expecting:
            if backup_cipher is None:
                raise UnexpectedPacketException(msgtype)
            else:
                raise UnexpectedPacketException(
                    msgtype, ord(backup_cipher.encrypt(chr(expecting)))
                )
        if not msg_spec[msgtype]:
            raise UnsupportedPacketException(msgtype)
        msg_parser = msg_spec[msgtype]
        msg = msg_parser.parse(stream)
    if title:
        if is_terminal:
            sys.stdout.write(t.move_up * 3)
        sys.stdout.write(t.bold_cyan("Received %s (0x%02x) packet" %
                                     (msg_parser.name,  msgtype)))
        if is_terminal:
            sys.stdout.write(t.move_down * 3)
        else:
            print
    PacketFormatter.print_packet(msg)
    if backup_cipher is not None:
        backup_cipher.encrypt(msg_parser.emit(msg))
    return msg


def send_packet(sock, msg_spec, msg, cipher=None):
    packet = msg_spec[msg['msgtype']]
    msgbytes = packet.emit(msg)
    print t.bold_cyan("\nSending %s (0x%02x) packet" % (packet.name,
                                                        msg['msgtype']))
    if cipher is None:
        print t.bold("Raw bytes:"), ''.join("%02x " % ord(c) for c in msgbytes)
    else:
        print t.bold("Raw bytes:      "),
        print ''.join("%02x " % ord(c) for c in msgbytes)
        msgbytes = cipher.encrypt(msgbytes)
        print t.bold("Encrypted bytes:"),
        print ''.join("%02x " % ord(c) for c in msgbytes)
    PacketFormatter.print_packet(msg)
    sock.sendall(msgbytes)


def multi_chunk_packet(radius=4):
    d = 1 + 2 * radius
    data = compress("".join(random_chunk() for i in range(d ** 2)))
    meta = [{'x': i / d - radius,
            'z': i % d - radius,
            'bitmap': 1,
            'add_bitmap': 0} for i in range(d ** 2)]
    return {'msgtype': 0x38,
            'chunks': {'data': data, 'metadata': meta}}


def random_chunk():
    block_ids = [chr(x) for x in range(1, 6)]
    blocks = "".join(choice(block_ids) for i in range(16 * 16 * 8))
    blocks += '\x00' * 8 * 16 * 16
    meta = '\x00' * 16 * 16 * 8
    light = '\x00' * 12 * 16 * 16 + '\xff' * 4 * 16 * 16
    biome = '\x01' * 16 * 16
    return blocks + meta + light + biome


def flat_chunk():
    blocks = '\x07' * 16 * 16
    blocks += '\x03' * 2 * 16 * 16
    blocks += '\x02' * 16 * 16
    blocks += '\x00' * 12 * 16 * 16
    meta = '\x00' * 16 * 16 * 8
    light = '\x00' * 10 * 16 * 16 + '\xff' * 6 * 16 * 16
    biome = '\x01' * 16 * 16
    return blocks + meta + light + biome


class UnexpectedPacketException(Exception):
    def __init__(self, id_, encrypted_id=None):
        self.id_ = id_
        self.encrypted_id = encrypted_id


class EOFException(Exception):
    pass


class StringSocket(object):
    def __init__(self):
        self.data = ""

    def send(self, data):
        self.data += data

    def sendall(self, data):
        self.send(data)


if __name__ == "__main__":
    (port, opts) = parse_args()

    try:
        Server(port, opts.send_chunks, opts.stay_connected).start()
    except KeyboardInterrupt:
        pass
