# This source file is part of mc3p, the Minecraft Protocol Parsing Proxy.
#
# Copyright (C) 2011 Matthew J. McGill

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

from mc3p.plugins import MC3Plugin, msghdlr

class FreecamPlugin(MC3Plugin):
    """Lets the client move and fly around without sending the packets
    to the real server

    Commands added:
        /freecam - toggles freecam mode
        /freecam back - returns the player to the last valid position
    """

    def init(self, args):
        self.freecam = False
        self.last_pos = None
        self.safe = True

        self.abilities = None

    def send_chat(self, chat_msg):
        self.to_client({'msgtype': 0x03, 'chat_msg': chat_msg})

    def is_safe(self, current_pos, threshold=4):
        get_coords = lambda m: (m['x'], m['y'], m['z'])
        result = map(lambda x, y: abs(x - y) < threshold,
            get_coords(current_pos), get_coords(self.last_pos))
        return not (False in result)

    @msghdlr(0x0a, 0x0b, 0x0c, 0x0d)
    def handle_position(self, msg, source):
        if source == 'client':
            if self.freecam:
                if msg['msgtype'] in (0x0b, 0x0d) and self.last_pos:
                    self.safe = self.is_safe(msg)
                return False
            elif msg['msgtype'] == 0x0d:
                self.last_pos = msg
        return True

    @msghdlr(0xca)
    def handle_abilities(self, msg, source):
        self.abilities = msg
        return True

    @msghdlr(0x03)
    def handle_chat(self, msg, source):
        if source == 'server':
            return True

        txt = msg['chat_msg']
        if txt.startswith('/freecam back'):
            if self.last_pos:
                self.send_chat("Returning to last position")
                self.to_client(self.last_pos)
                self.safe = True
            else:
                self.send_chat("No saved position")
            return False
        elif txt.startswith('/freecam'):
            
            if self.freecam and not self.safe:
                self.send_chat("Please use '/freecam back' to go back "
                    "to a safe position")
                return False

            self.freecam = not self.freecam

            if self.abilities:
                if self.freecam:
                    new_abilities = self.abilities.copy()
                    new_abilities['allow_flying'] = True
                    self.to_client(new_abilities)
                else:
                    # restore old ones
                    self.to_client(self.abilities)
            
            self.send_chat("Freecam mode is now [%s]" %
                ('ON' if self.freecam else 'OFF'))

            return False
        return True
