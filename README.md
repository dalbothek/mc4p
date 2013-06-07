
## What is mc4p?

mc4p (short for Minecraft Portable Protocol-Parsing Proxy) is a Minecraft proxy
server. With mc4p, you can create programs (mc4p plugins) that examine
and modify messages sent between the Minecraft client and server without
writing any multi-threaded or network-related code.

mc4p is a fork of [mmgcill](https://github.com/mmcgill)'s [mc3p](https://github.com/mmcgill/mc3p).

### Installing from source

To install from source, just clone the GitHub repository. You can then run
mc4p directly from the top-level directory of the repository, or install
it in 'development' mode with

    python setup.py develop

If mc4p is installed in 'development' mode, you can uninstall it with

    python setup.py develop --uninstall

### Dependencies

* [Python 2.7](http://www.python.org/download/releases/2.7.3/)
* [setuptools](http://pypi.python.org/pypi/setuptools)

#### Linux / Mac OS X
* [libevent](http://libevent.org/)

#### Windows
* [gevent](https://github.com/SiteSupport/gevent/downloads)
* pycrypto ([32bit](http://www.dragffy.com/wp-content/uploads/2011/11/pycrypto-2.4.1.win32-py2.7.exe) | [64bit](http://dl.dropbox.com/u/90067063/pycrypto-2.6.win-amd64-py2.7.exe))

## Running mc4p.

To start an mc4p server that listens on port 25566 and forwards connections
to a Minecraft server:

    $ python -m mc4p.proxy -p 25566 <server>

Within your Minecraft client, you can then connect to <server> through
mc4p using the server address 'localhost:25566'. However, to do anything useful
you must enable some plugins.

## Using mc4p plugins.

An mc4p plugin has complete control over all the messages that pass between
the Minecraft client and server. By manipulating messages sent between client
and server, you can add useful functionality without modifying client or server
code.

To run a plugin, you must enable it with the --plugin <name> option when you start mc4p.
All enabled plugins are initialized after a client successfully connects to a server.
For example, to run the mute example plugin that comes with mc4p:

    $ python -m mc4p.proxy --plugin 'mc4p.plugin.mute' <server>

Some plugins accept arguments that modify their behavior. To pass arguments
to a plugin, enclose them in parentheses following the plugin's name, like so:
--plugin '<name>(<arguments>)'. Be sure to use quotes, or escape the parentheses
as required by your shell.

    $ python -m mc4p.proxy --plugin '<plugin>(<arguments>)' <server>

## A Plugin Example: mute

The 'mute' plugin is provided as a simple example of mc4p's flexibility.
This plugin allows a player to mute chat messages from selected players on a
server. It requires no modification to either the Minecraft client or server.

Give it a try: start mc4p with the 'mute' plugin enabled:

    $ python -m mc4p.proxy --plugin 'mc4p.plugin.mute' your.favorite.server.com

You can now mute a player by typing '/mute NAME' in chat,
and unmute them with '/unmute NAME'. You can display muted players with '/muted'.

The plugin works by intercepting all Minecraft chat messages, and silently
discarding those sent by muted players.

Now take a look at the source code for the 'mute' plugin:

    from mc4p.plugins import mc4plugin, msghdlr

    class MutePlugin(mc4plugin):
        """Lets the client mute players, hiding their chat messages.

        The client controls the plugin with chat commands:
            /mute NAME      Hide all messages from player NAME.
            /unmute NAME    Allow messages from player NAME.
            /muted          Show the list of currently muted players.
        """
        def init(self, args):
            self.muted_set = set() # Set of muted player names.

        def send_chat(self, chat_msg):
            """Send a chat message to the client."""
            self.to_client({'msgtype': 0x03, 'chat_msg': chat_msg})

        def mute(self, player_name):
            self.muted_set.add(player_name)
            self.send_chat('Muted %s' % player_name)

        def unmute(self, player_name):
            if player_name in self.muted_set:
                self.muted_set.remove(player_name)
                self.send_chat('Unmuted %s' % player_name)
            else:
                self.send_chat('%s is not muted' % player_name)

        def muted(self):
            self.send_chat('Currently muted: %s' % ', '.join(self.muted_set))

        @msghdlr(0x03)
        def handle_chat(self, msg, source):
            txt = msg['chat_msg']
            if source == 'client':
                # Handle mute commands
                if txt.startswith('/mute '):     self.mute(txt[len('/mute '):])
                elif txt.startswith('/unmute '): self.unmute(txt[len('/unmute '):])
                elif txt == '/muted':            self.muted()
                else: return True # Forward all other chat messages.

                return False # Drop mute plugin commands.
            else:
                # Drop messages containing the string <NAME>, where NAME is a muted player name.
                return not any(txt.startswith('<%s>' % name) for name in self.muted_set)

Every mc4p plugin is a Python module that contains a single *plugin class*, a
subclass of mc4plugin. A plugin must contain *exactly* one plugin class;
mc4p will print an error if multiple sub-classes of mc4plugin are found.

Once a client successfully connects to a server through the proxy, mc4p
creates an instance of the plugin class of each enabled plugin, and calls its
'init' method. Plugin classes should override 'init' to perform plugin-specific
set-up. If the plugin was enabled with an argument string, that string is passed in
the 'args' parameter; otherwise, 'args' is None.

A plugin class registers a *message handler* for every message type it wishes
to receive. To register a method of a plugin class as a message handler, decorate
it with '@msghdlr'. The '@msghdlr' decorator takes one or more message types
as arguments. Each message handler should take two arguments (in addition to 'self'):

* 'msg', a dictionary representing the message, and
* 'source', which indicates the sender of the message; source is either
  'client' or 'server'.

The 'msg' dictionary always maps the key 'msgtype' to the message's type, a
number between 0 and 0xFF. If
your message handler is registered for multiple types, you can determine the type
of a given message by checking `msg['msgtype']`. The other key-value pairs
in the 'msg' dictionary depend on the specific message type. See
[messages.py](https://github.com/mmcgill/mc4p/blob/master/mc4p/messages.py)
for a definition of the keys associated with each message type.

A message handler returns a boolean value indicating whether the message should
be forwarded to its destination. A return value of True forwards the message,
while a return value of False silently drops it. The message handler may also
modify the message by changing the values of the 'msg' dictionary, and
returning True.

The mute plugin registers the 'handle_chat' method as a message handler for
messages of type '0x03', which represent chat messages. If the chat message
is sent from the client, we check to see if it is a command to the mute plugin.
If so, then we process it, and drop it by returning False. If not, we forward it
by returning True. If the chat message is from the server, then we forward it
if it was not sent by a currently blocked player.

Along with modifying or dropping messages, a plugin can create new messages
by passing a 'msg' dictionary with a 'msgtype' and all relevant key-value pairs
to the 'to_client' or 'to_server methods, which are defined in the mc4plugin class.

The mute plugin uses the 'to_client' method to inject chat messages that indicate
the result of each command issued by the user. Note that since these messages
are sent to the client, and not the server, they are not visible to any other
user on the server.

