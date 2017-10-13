"""Helper code for dealing with protobuf messages."""

import binascii

from pyatv.mrp import tlv8

# Import all supported messages here, otherwise they will not be decoded
# properly when printing them in the debug messages
from pyatv.mrp.protobuf import NotificationMessage_pb2  # noqa
from pyatv.mrp.protobuf import ClientUpdatesConfigMessage_pb2 as ClientUpdates
from pyatv.mrp.protobuf import ProtocolMessage_pb2 as PB  # noqa
from pyatv.mrp.protobuf import DeviceInfoMessage_pb2 as DeviceInfoMessage
from pyatv.mrp.protobuf import CryptoPairingMessage_pb2 as CryptoPairingMessage
from pyatv.mrp.protobuf import SetStateMessage_pb2 as SetStateMessage
from pyatv.mrp.protobuf import TransactionMessage_pb2 as TransactionMessage
from pyatv.mrp.protobuf import VolumeControlAvailability_pb2 as VolumeControlAvailabilityMessage  # noqa
from pyatv.mrp.protobuf import SetArtworkMessage_pb2 as SetArtworkMessage
from pyatv.mrp.protobuf import SendPackedVirtualTouchEventMessage_pb2 as SendPackedVirtualTouchEventMessage  # noqa
from pyatv.mrp.protobuf import RegisterHIDDeviceMessage_pb2 as RegisterHIDDeviceMessage
from pyatv.mrp.protobuf import RegisterHIDDeviceResultMessage_pb2 as RegisterHIDDeviceResultMessage
from pyatv.mrp.protobuf import SendHIDEventMessage_pb2 as SendHIDEventMessage


def create(message_type, priority=0):
    """Create a ProtocolMessage."""
    message = PB.ProtocolMessage()
    message.type = message_type
    message.priority = priority
    return message


# TODO: default information here for the moment
def device_information(name, identifier):
    """Create a new DEVICE_INFO_MESSAGE."""
    # pylint: disable=no-member
    message = create(PB.ProtocolMessage.DEVICE_INFO_MESSAGE)
    # pylint: disable=no-member
    info = message.Extensions[DeviceInfoMessage.deviceInfoMessage]
    info.uniqueIdentifier = identifier
    info.name = name
    info.localizedModelName = 'iPhone'
    info.systemBuildVersion = '14G60'
    info.applicationBundleIdentifier = 'com.apple.TVRemote'
    info.applicationBundleVersion = '273.12'
    info.protocolVersion = 1
    return message


def crypto_pairing(pairing_data):
    """Create a new CRYPTO_PAIRING_MESSAGE."""
    # pylint: disable=no-member
    message = create(PB.ProtocolMessage.CRYPTO_PAIRING_MESSAGE)
    # pylint: disable=no-member
    crypto = message.Extensions[CryptoPairingMessage.cryptoPairingMessage]
    crypto.status = 0
    crypto.pairingData = tlv8.write_tlv(pairing_data)
    return message


def client_updates_config(artwork=True, now_playing=True,
                          volume=True, keyboard=True):
    """Create a new CLIENT_UPDATES_CONFIG_MESSAGE."""
    message = create(PB.ProtocolMessage.CLIENT_UPDATES_CONFIG_MESSAGE)
    config = message.Extensions[ClientUpdates.clientUpdatesConfigMessage]
    config.artworkUpdates = artwork
    config.nowPlayingUpdates = now_playing
    config.volumeUpdates = volume
    config.keyboardUpdates = keyboard
    return message

def wake_device():
    """Create a new WAKE_DEVICE_MESSAGE."""
    return create(PB.ProtocolMessage.WAKE_DEVICE_MESSAGE)

def register_hid_device(screen_width, screen_height,
                        absolute=False, integrated_display=False):
    """Create a new REGISTER_HID_DEVICE_MESSAGE."""
    message = create(PB.ProtocolMessage.REGISTER_HID_DEVICE_MESSAGE)
    ext = RegisterHIDDeviceMessage.registerHIDDeviceMessage
    descriptor = message.Extensions[ext].deviceDescriptor
    descriptor.absolute = 1 if absolute else 0
    descriptor.integratedDisplay = 1 if integrated_display else 0
    descriptor.screenSizeWidth = screen_width
    descriptor.screenSizeHeight = screen_height
    return message

def send_packed_virtual_touch_event(x, y, phase, deviceID, finger):
    """Create a new WAKE_DEVICE_MESSAGE."""
    message = create(PB.ProtocolMessage.SEND_PACKED_VIRTUAL_TOUCH_EVENT_MESSAGE)
    ext = SendPackedVirtualTouchEventMessage.sendPackedVirtualTouchEventMessage
    event = message.Extensions[ext]

    # The packed version of VirtualTouchEvent contains X, Y, phase, deviceID
    # and finger stored as a byte array. Each value is written as 16bit little
    # endian integers.
    event.data = x.to_bytes(2, byteorder='little')
    event.data += y.to_bytes(2, byteorder='little')
    event.data += phase.to_bytes(2, byteorder='little')
    event.data += deviceID.to_bytes(2, byteorder='little')
    event.data += finger.to_bytes(2, byteorder='little')

    return message

def send_hid_event(use_page, usage, down):
    """Create a new SEND_HID_EVENT_MESSAGE."""
    message = create(PB.ProtocolMessage.SEND_HID_EVENT_MESSAGE)
    ext = SendHIDEventMessage.sendHIDEventMessage
    event = message.Extensions[ext]

    # TODO: This should be generated somehow. I guess it's mach AbsoluteTime
    # which is tricky to generate. The device does not seem to care much about
    # the value though, so hardcode something here.
    abstime = binascii.unhexlify(b'438922cf08020000')

    data = use_page.to_bytes(2, byteorder='big')
    data += usage.to_bytes(2, byteorder='big')
    data += (1 if down else 0).to_bytes(2, byteorder='big')

    # This is the format that the device expects. Some day I might take some
    # time to decode it for real, but this is fine for now.
    event.hidEventData = abstime + \
        binascii.unhexlify(b'00000000000000000100000000000000020' +
                           b'00000200000000300000001000000000000') + \
        data + \
        binascii.unhexlify(b'0000000000000001000000')

    return message
