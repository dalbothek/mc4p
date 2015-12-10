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

import re


class StringEnum(object):
    """

    """
    def __init__(self, *values):
        self._values = values
        for value in values:
            setattr(self, value, value)

    def __getitem__(self, index):
        return self._values[index]

    def index(self, value):
        return self._values.index(value)

    def __iter__(self):
        return iter(self._values)


class CombinedMemoryView(object):
    """
    Combines multiple memoryviews into one without copying anything.

    CombinedMemoryView objects have a very similar API as memoryviews do,
    however many low-level functions won't accept such an object in place
    of a memoryview. In these cases it might be necessary to iterate over
    the objects data_parts:

      for data_part in combined_memory_view.data_parts:
        socket.sendall(data_part)
    """
    def __init__(self, *data_parts):
        self.data_parts = []
        for part in data_parts:
            if isinstance(part, CombinedMemoryView):
                self.data_parts += part.data_parts
            else:
                self.data_parts.append(part)
        self.length = sum(len(part) for part in data_parts)

    def __getitem__(self, key):
        if isinstance(key, int):
            if key < 0:
                key = self.length + key

            pos = 0
            for part in self.data_parts:
                if pos + len(part) > key:
                    return part[key - pos]
                pos += len(part)
            raise IndexError("Index out of range")

        elif isinstance(key, slice):
            if key.step is not None and key.step != 1:
                raise NotImplementedError()

            start = key.start if key.start >= 0 else key.start + self.length
            stop = key.stop if key.stop >= 0 else key.stop + self.length

            included_parts = []

            pos = 0
            for part in self.data_parts:
                if stop <= pos:
                    break
                if start <= pos:
                    included_parts.append(part[:stop - pos])
                elif start < pos + len(part):
                    included_parts.append(part[start - pos:stop - pos])
                pos += len(part)

            return CombinedMemoryView(*included_parts)

        else:
            raise TypeError("Key needs to be an integer")

    def append(self, data):
        if isinstance(data, CombinedMemoryView):
            self.data_parts += data.data_parts
        else:
            self.data_parts.append(data)
        self.length += len(data)

    def tobytes(self):
        return b"".join(
            part.tobytes() if isinstance(part, memoryview) else part
            for part in self.data_parts
        )

    def __len__(self):
        return self.length


COLOR_PATTERN = re.compile("§.")


def parse_chat(chat_obj):
    """
    Reduces a JSON chat object to a string with all formatting removed.
    """
    if isinstance(chat_obj, basestring):
        return strip_color(chat_obj)
    elif not isinstance(chat_obj, dict):
        return ""

    if isinstance(chat_obj.get('text'), basestring):
        text = chat_obj['text']
    elif isinstance(chat_obj.get('translate'), basestring):
        if "with" in chat_obj and isinstance(chat_obj['with'], list):
            args = ", ".join(
                arg for arg in chat_obj['with'] if isinstance(arg, basestring)
            )
        else:
            args = ""
        text = "<%s(%s)>" % (chat_obj['translate'], args)
    elif isinstance(chat_obj.get('selector'), basestring):
        text = chat_obj['selector']
    else:
        text = ""

    if isinstance(chat_obj.get('extra'), list):
        text += "".join(parse_chat(extra) for extra in chat_obj['extra'])

    return strip_color(text)


def strip_color(string):
    return COLOR_PATTERN.sub("", string)
