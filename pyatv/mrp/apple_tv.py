"""Implementation of the MediaRemoteTV Protocol used by ATV4 and later."""

import logging
import asyncio

from pyatv.mrp import prototype
from pyatv.interface import (AppleTV, RemoteControl, Metadata,
                             Playing, PushUpdater)

_LOGGER = logging.getLogger(__name__)


class MrpRemoteControl(RemoteControl):
    """Implementation of API for controlling an Apple TV."""

    pass


class MrpPlaying(Playing):
    """Implementation of API for retrieving what is playing."""

    pass


class MrpMetadata(Metadata):
    """Implementation of API for retrieving metadata."""

    pass


class MrpPushUpdater(PushUpdater):
    """Implementation of API for handling push update from an Apple TV."""

    pass


# TODO: This is PURE prototype stuff. It _must_ be re-written, but with this
# code at least some testing can be performed.
class MrpPairingHandler(object):
    """Base class for API used to pair with an Apple TV."""

    def __init__(self, loop, address, port):
        print("address: {0}, port: {1}".format(address, port))
        self.factory = prototype.MessageFactory()
        self.net = prototype.TempNetwork(address, port, loop)
        self.pairing_id = '6fdad309-5331-47ff-b525-1158bb105af1'.encode()
        self.atv_pub_key = None
        self.atv_identifier = None
        self.ltsk = None

    @property
    def has_paired(self):
        """If a successful pairing has been performed.

        The value will be reset when stop() is called.
        """
        raise exceptions.NotSupportedError

    @asyncio.coroutine
    def start(self, **kwargs):
        """Start pairing process."""
        yield from self.net.connect()
        yield from prototype.device_information(self.net)
        atv_pub_key, atv_identifier, ltsk = yield from prototype.pair(
            self.net, self.factory, self.pairing_id)
        self.atv_pub_key = atv_pub_key
        self.atv_identifier = atv_identifier
        self.ltsk = ltsk
        print("PUB KEY: {0}\nID: {1}\nLTSK: {2}\nPairing ID: {3}".format(
                self.atv_pub_key, self.atv_identifier,
                self.ltsk, self.pairing_id))

    @asyncio.coroutine
    def stop(self, **kwargs):
        """Stop pairing process."""
        c2a_key, a2c_key = yield from prototype.verify(
            self.net, self.factory, self.atv_pub_key, self.atv_identifier,
            self.ltsk, self.pairing_id)

        self.net.enable_encryption(c2a_key, a2c_key)

        # Dummy code where messages can be sent when testing
        yield from self.send_messages()

    @asyncio.coroutine
    def send_messages(self):
        from pyatv.mrp.protobuf import ProtocolMessage_pb2 as PB
        import pyatv.mrp.protobuf.ClientUpdatesConfigMessage_pb2 as ClientUpdatesConfigMessage
        message = self.factory.make(PB.ProtocolMessage.CLIENT_UPDATES_CONFIG_MESSAGE, add_identifier=False)
        config = message.Extensions[ClientUpdatesConfigMessage.clientUpdatesConfigMessage]
        config.artworkUpdates = True
        config.nowPlayingUpdates = True
        config.volumeUpdates = True
        config.keyboardUpdates = True
        self.net.send(message)

        _LOGGER.debug("Waiting for messages...")
        recv = None
        while recv != b'':
            recv = yield from self.net.receive()

    @asyncio.coroutine
    def set(self, key, value, **kwargs):
        """Set a process specific value.

        The value is specific to the device being paired with and can for
        instance be a PIN code.
        """
        raise exceptions.NotSupportedError

    @asyncio.coroutine
    def get(self, key):
        """Retrieve a process specific value."""
        raise exceptions.NotSupportedError


class MrpAppleTV(AppleTV):
    """Implementation of API support for Apple TV."""

    # This is a container class so it's OK with many attributes
    # pylint: disable=too-many-instance-attributes
    def __init__(self, loop, session, details, airplay):
        """Initialize a new Apple TV."""
        super().__init__()

        self._service = details.usable_service()
        self._atv_remote = MrpRemoteControl()
        self._atv_metadata = MrpMetadata()
        self._atv_push_updater = MrpPushUpdater()
        self._atv_pairing = MrpPairingHandler(
            loop, details.address, self._service.port)
        self._airplay = airplay

    @asyncio.coroutine
    def login(self):
        """Perform an explicit login."""
        _LOGGER.debug('Login called')

    @asyncio.coroutine
    def logout(self):
        """Perform an explicit logout.

        Must be done when session is no longer needed to not leak resources.
        """
        _LOGGER.debug('Logout called')

    @property
    def service(self):
        """Return service used to connect to the Apple TV.."""
        return self._service

    @property
    def pairing(self):
        """Return API for pairing with the Apple TV."""
        return self._atv_pairing

    @property
    def remote_control(self):
        """Return API for controlling the Apple TV."""
        return self._atv_remote

    @property
    def metadata(self):
        """Return API for retrieving metadata from Apple TV."""
        return self._atv_metadata

    @property
    def push_updater(self):
        """Return API for handling push update from the Apple TV."""
        return self._atv_push_updater

    @property
    def airplay(self):
        """Return API for working with AirPlay."""
        return self._airplay
