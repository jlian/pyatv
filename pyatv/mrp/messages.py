"""Helper code for dealing with protobuf messages."""

from pyatv.mrp import tlv8

# Import all supported messages here, otherwise they will not be decoded
# properly when printing them in the debug messages
from pyatv.mrp.protobuf import NotificationMessage_pb2  # noqa
from pyatv.mrp.protobuf import ClientUpdatesConfigMessage_pb2 as ClientUpdates
from pyatv.mrp.protobuf import ProtocolMessage_pb2 as PB  # noqa
from pyatv.mrp.protobuf import DeviceInfoMessage_pb2 as DeviceInfoMessage
from pyatv.mrp.protobuf import CryptoPairingMessage_pb2 as CryptoPairingMessage


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
