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

import Queue
import logging
import messages
import multiprocessing
import traceback

### Globals ###

logger = logging.getLogger(__name__)


### Exceptions ###
class ConfigError(Exception):
    def __init__(self, msg):
        Exception.__init__(self)
        self.msg = msg

    def __str__(self):
        return self.msg


class PluginError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class PluginConfig(object):
    """Store plugin configuration"""
    def __init__(self):
        self.__ids = []
        self.__plugin_names = {}  # { id -> plugin_name }
        self.__argstrs = {}       # { id -> argstr }
        self.__orderings = {}     # { msgtype -> [id1, id2, ...] }

    def __default_id(self, plugin_name):
        id = plugin_name
        i = 1
        while id in self.__ids:
            id = plugin_name + str(i)
            i += 1
        return id

    def add(self, plugin_name, id=None, argstr=''):
        if id is None:
            id = self.__default_id(plugin_name)
        if id in self.__ids:
            raise ConfigError("Duplicate id '%s'" % id)
        self.__ids.append(id)
        self.__plugin_names[id] = plugin_name
        self.__argstrs[id] = argstr
        return self

    def order(self, msgtype, id_list):
        if len(set(id_list)) != len(id_list):
            raise ConfigError("Duplicate ids in %s" % repr(id_list))
        unknown_ids = set(self.__ids) - set(id_list)
        if len(unknown_ids) > 0:
            raise ConfigError("No such ids: %s" % repr(unknown_ids))
        self.__orderings[msgtype] = id_list
        return self

    @property
    def ids(self):
        """List of instance ids."""
        return list(self.__ids)

    @property
    def plugins(self):
        """Set of instantiated plugin names."""
        return set(self.__plugin_names.values())

    @property
    def plugin(self):
        """Map of ids to plugin names."""
        return dict(self.__plugin_names)

    @property
    def argstr(self):
        """Map of ids to argument strings."""
        return dict(self.__argstrs)

    def ordering(self, msgtype):
        """Return a total ordering of instance ids for this msgtype."""
        if not msgtype in self.__orderings:
            return self.ids
        else:
            o = list(self.__orderings[msgtype])
            for id in self.__ids:
                if not id in o:
                    o.append(id)
            return o


class PluginManager(object):
    """Manage plugins for an mc4p session."""
    def __init__(self, config, cli_proxy, srv_proxy):
        # Map of plugin name to module.
        self.__plugins = {}

        # Map of instance ID to MC4Plugin instance.
        self.__instances = {}

        # Holds the active protocol after successful handshake.
        self.__protocol = messages.protocol[0]

        # For asynchronously injecting messages from the client or server.
        self.__from_client_q = multiprocessing.Queue()
        self.__from_server_q = multiprocessing.Queue()

        # Plugin configuration.
        self.__config = config

        self._load_plugins()
        self._instantiate_all()

    def next_injected_msg_from(self, source):
        """Return the Queue containing source's messages to be injected."""
        if source == 'client':
            q = self.__from_client_q
        elif source == 'server':
            q = self.__from_server_q
        else:
            raise Exception('Unrecognized source ' + source)
        try:
            return q.get(block=False)
        except Queue.Empty:
            return None

    def _load_plugins(self):
        """Load or reload all plugins."""
        logger.info('%s loading plugins' % repr(self))
        for pname in self.__config.plugins:
            self._load_plugin(pname)

    def _load_plugin(self, pname):
        """Load or reload plugin pname."""
        try:
            logger.debug('  Loading %s' % pname)
            mod = __import__(pname)
            for p in pname.split('.')[1:]:
                mod = getattr(mod, p)
            self.__plugins[pname] = reload(mod)
        except Exception as e:
            logger.error("Plugin %s failed to load: %s" % (pname, str(e)))
            return

    def _instantiate_all(self):
        """Instantiate plugins based on self.__config.

        Assumes plugins have already been loaded.
        """
        logger.info('%s instantiating plugins' % repr(self))
        for id in self.__config.ids:
            pname = self.__config.plugin[id]
            if not pname in self.__plugins:
                continue
            else:
                self._instantiate_one(id, pname)

    def _update_protocol_version(self, version):
        self.__protocol = messages.protocol[version]
        for plugin in self.__instances.itervalues():
            plugin._set_protocol(self.__protocol)

    def _find_plugin_class(self, pname):
        """Return the subclass of MC4Plugin in pmod."""
        pmod = self.__plugins[pname]
        class_check = lambda c: \
            c != MC4Plugin and isinstance(c, type) and issubclass(c, MC4Plugin)
        classes = filter(class_check, pmod.__dict__.values())
        if len(classes) == 0:
            logger.error(
                "Plugin '%s' does not contain a subclass of MC4Plugin" % pname
            )
            return None
        elif len(classes) > 1:
            logger.error(
                "Plugin '%s' contains multiple subclasses of MC4Plugin: %s" %
                (pname, ', '.join([c.__name__ for c in classes]))
            )
        else:
            return classes[0]

    def _instantiate_one(self, id, pname):
        """Instantiate plugin pmod with id."""
        clazz = self._find_plugin_class(pname)
        if None == clazz:
            return
        try:
            logger.debug("  Instantiating plugin '%s' as '%s'" % (pname, id))
            inst = clazz(self.__protocol,
                         self.__from_client_q,
                         self.__from_server_q)
            inst.init(self.__config.argstr[id])
            self.__instances[id] = inst
        except Exception as e:
            logger.error("Failed to instantiate '%s': %s" % (id, str(e)))

    def destroy(self):
        """Destroy plugin instances."""
        self.__plugins = {}
        logger.info("%s destroying plugin instances" % repr(self))
        for iname in self.__instances:
            logger.debug("  Destroying '%s'" % iname)
            try:
                self.__instances[iname]._destroy()
            except:
                logger.error(
                    "Error cleaning up instance '%s' of plugin '%s'" %
                    (iname, self.__config.plugin[iname])
                )
                logger.error(traceback.format_exc())
        self.__instances = {}

    def filter(self, msg, source):
        """Filter msg through the configured plugins.

        Returns True if msg should be forwarded, False otherwise.
        """
        if 0x02 == msg.id:
            self._update_protocol_version(msg.version)
            logger.debug('PluginManager detected proto version %d' %
                         self.__protocol.version)
        return self._call_plugins(msg, source)

    def _call_plugins(self, msg, source):
        msgtype = msg.id
        for id in self.__config.ordering(msgtype):
            inst = self.__instances.get(id, None)
            if inst and not inst.filter(msg, source):
                return False
        return True

    def __repr__(self):
        return '<PluginManager>'


class MsgHandlerWrapper(object):
    def __init__(self, msgtypes, method):
        self.msgtypes = msgtypes
        self.method = method

    def __call__(self, *args, **kargs):
        self.method(*args, **kargs)


def msghdlr(*msgtypes):
    def wrapper(f):
        return MsgHandlerWrapper(msgtypes, f)
    return wrapper


class MC4Plugin(object):
    """Base class for mc4p plugins."""

    def __init__(self, protocol, from_client, from_server):
        self.__protocol = protocol
        self.__to_client = from_server
        self.__to_server = from_client
        self.__hdlrs = {}
        self._collect_msg_hdlrs()

    def _set_protocol(self, protocol):
        self.__protocol = protocol

    def _collect_msg_hdlrs(self):
        wrappers = filter(lambda x: isinstance(x, MsgHandlerWrapper),
                          self.__class__.__dict__.values())
        for wrapper in wrappers:
            self._unwrap_hdlr(wrapper)

    def _unwrap_hdlr(self, wrapper):
        hdlr = wrapper.method
        name = hdlr.__name__
        for msgtype in wrapper.msgtypes:
            if msgtype in self.__hdlrs:
                othername = self.__hdlrs[msgtype].__name__
                raise PluginError('Multiple handlers for %x: %s, %s' %
                                  (msgtype, othername, name))
            else:
                self.__hdlrs[msgtype] = hdlr
                logger.debug('  registered handler %s for %x'
                             % (name, msgtype))

    def init(self, args):
        """Initialize plugin instance.
        Override to provide subclass-specific initialization."""

    def destroy(self):
        """Free plugin resources.
        Override in subclass."""

    def _destroy(self):
        """Internal cleanup, do not override."""
        self.__to_client.close()
        self.__to_server.close()
        self.destroy()

    def create_packet(self, msg_id, side=None, **fields):
        if self.__protocol[msg_id] is None:
            logger.error(("Plugin %s tried to send message with "
                          "unrecognized type %d") %
                         (self.__class__.__name__, msg_id))
            return None
        try:
            msg = self.__protocol[msg_id](side=side, **fields)
            msg.emit()
        except:
            logger.error("Plugin %s sent invalid message of type %d" %
                         (self.__class__.__name__, msg_id))
            logger.info(traceback.format_exc())
            if msg:
                logger.debug("  msg: %s" % repr(msg))
            return None
        return msg

    def to_server(self, msg, **fields):
        """Send msg to the server asynchronously."""
        if type(msg) == int:
            msg = self.create_packet(msg, "client", **fields)
        self.__to_server.put(msg)

    def to_client(self, msg, **fields):
        """Send msg to the client asynchronously."""
        if type(msg) == int:
            msg = self.create_packet(msg, "server", **fields)
        self.__to_client.put(msg)

    def default_handler(self, msg, source):
        """Default message handler for all message types.

        Override in subclass to filter all message types."""
        return True

    def filter(self, msg, source):
        """Filter msg via the appropriate message handler(s).

        Returns True to forward msg on, False to drop it.
        Modifications to msg are passed on to the recipient.
        """
        msgtype = msg.id
        try:
            if not self.default_handler(msg, source):
                return False
        except:
            logger.error('Error in default handler of plugin %s:\n%s' %
                         (self.__class__.__name__, traceback.format_exc()))
            return True

        try:
            if msgtype in self.__hdlrs:
                return self.__hdlrs[msgtype](self, msg, source)
            else:
                return True
        except:
            hdlr = self.__hdlrs[msgtype]
            logger.error('Error in handler %s of plugin %s: %s' %
                         (hdlr.__name__, self.__class__.__name__,
                          traceback.format_exc()))
            return True
