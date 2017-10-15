#!/usr/bin/env python3
#
# This is a quick-hack that extends ProtocolMessage with a method called inner
# that will return the correct submessage based on the type.
#
# Update with this command:
# ./scripts/autogen_protobuf_extensions.py > pyatv/mrp/protobuf/__init__.py
#
"""Simple hack to auto-generate protobuf handling code."""

import sys
import os
from collections import namedtuple


BASE_PACKAGE = 'pyatv.mrp.protobuf'
OUTPUT_TEMPLATE = """\"\"\"Simplified extension handling for protobuf messages.

THIS CODE IS AUTO-GENERATED - DO NOT EDIT!!!
\"\"\"

from pyatv.mrp.protobuf.ProtocolMessage_pb2 import ProtocolMessage


{package_imports}


{message_imports}


_EXTENSION_LOOKUP = {{
    {extensions}
}}


{constants}


def _inner_message(self):
    extension = _EXTENSION_LOOKUP.get(self.type, None)
    if extension:
        return self.Extensions[extension]

    raise Exception('unknown type: ' + str(self.type))


ProtocolMessage.inner = _inner_message
"""

MessageInfo = namedtuple('MessageInfo',
                         ['module', 'title', 'accessor', 'const'])


def extract_message_info():
    """Get information about all messages of interest."""
    lookup_table = {}
    base_path = BASE_PACKAGE.replace('.', '/')
    filename = os.path.join(base_path, 'ProtocolMessage.proto')

    with open(filename, 'r') as file:
        types_found = False

        for line in file:
            stripped = line.lstrip().rstrip()

            # Look for the Type enum
            if stripped == 'enum Type {':
                types_found = True
                continue
            elif types_found and stripped == '}':
                break
            elif not types_found:
                continue

            constant = stripped.split(' ')[0]
            title = constant.title().replace(
                '_', '').replace('Hid', 'HID')  # Hack...
            accessor = title[0].lower() + title[1:]

            if not os.path.exists(os.path.join(base_path, title + '.proto')):
                continue

            lookup_table[constant] = MessageInfo(
                title + '_pb2', title, accessor, constant)

    return lookup_table


def main():
    """Script starts somewhere around here."""
    lookup_table = extract_message_info()

    package_imports = []
    message_imports = []
    message_extensions = []
    message_constants = []

    # Extract everything needed to generate output file
    for message in lookup_table.values():
        package_imports.append(
            'from {0} import {1}'.format(
                BASE_PACKAGE, message.module))

    for message in lookup_table.values():
        message_imports.append(
            'from {0}.{1} import {2}'.format(
                BASE_PACKAGE, message.module, message.title))

    for message in lookup_table.values():
        message_extensions.append(
            'ProtocolMessage.{0}: {1}.{2},'.format(
                message.const, message.module, message.accessor))

    for message in lookup_table.values():
        message_constants.append(
            '{0} = ProtocolMessage.{0}'.format(message.const))

    # Print file output with values inserted
    print(OUTPUT_TEMPLATE.format(
        package_imports='\n'.join(package_imports),
        message_imports='\n'.join(message_imports),
        extensions='\n    '.join(message_extensions),
        constants='\n'.join(message_constants)))

    return 0


if __name__ == '__main__':
    sys.exit(main())
