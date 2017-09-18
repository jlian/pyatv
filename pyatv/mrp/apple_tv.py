"""Implementation of the MediaRemoteTV Protocol used by ATV4 and later."""

import logging
import asyncio

from pyatv import exceptions
from pyatv.mrp import messages
from pyatv.mrp.srp import (Credentials, SRPAuthHandler)
from pyatv.mrp.connection import MrpConnection
from pyatv.mrp.pairing import (MrpPairingProcedure, MrpPairingVerifier)
from pyatv.interface import (AppleTV, RemoteControl, Metadata,
                             Playing, PushUpdater, PairingHandler)

_LOGGER = logging.getLogger(__name__)


class MrpRemoteControl(RemoteControl):
    """Implementation of API for controlling an Apple TV."""

    def __init__(self, tmp):
        self.tmp = tmp

    @asyncio.coroutine
    def stop(self):
        """Press key stop."""
        # TODO: This does nothing at the moment and lacks connection abstraction
        yield from self.tmp.login()


class MrpPlaying(Playing):
    """Implementation of API for retrieving what is playing."""

    pass


class MrpMetadata(Metadata):
    """Implementation of API for retrieving metadata."""

    pass


class MrpPushUpdater(PushUpdater):
    """Implementation of API for handling push update from an Apple TV."""

    pass


class MrpPairingHandler(PairingHandler):
    """Base class for API used to pair with an Apple TV."""

    def __init__(self, loop, connection, srp):
        """Initialize a new MrpPairingHandler."""
        self.connection = connection
        self.srp = srp
        self.pairing_procedure = MrpPairingProcedure(self.connection, self.srp)
        self.credentials = None

    @property
    def has_paired(self):
        """If a successful pairing has been performed.

        The value will be reset when stop() is called.
        """
        return self.credentials is not None

    @asyncio.coroutine
    def start(self, **kwargs):
        """Start pairing process."""
        yield from self.connection.connect()

        # TODO: do not hardcode parameters
        message = messages.device_information(
            'pyatv', '6fdad309-5331-47ff-b525-1158bb105af1')
        self.connection.send(message)
        yield from self.connection.receive()

        yield from self.pairing_procedure.start_pairing()

    @asyncio.coroutine
    def stop(self, **kwargs):
        """Stop pairing process."""
        # Finish off pairing process
        pin = int(kwargs['pin'])
        self.credentials = yield from self.pairing_procedure.finish_pairing(pin)

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
        if key == 'credentials' and self.credentials:
            return str(self.credentials)


class MrpAppleTV(AppleTV):
    """Implementation of API support for Apple TV."""

    # This is a container class so it's OK with many attributes
    # pylint: disable=too-many-instance-attributes
    def __init__(self, loop, session, details, airplay):
        """Initialize a new Apple TV."""
        super().__init__()

        self._session = session
        self._service = details.usable_service()

        self._connection = MrpConnection(
            details.address, self._service.port, loop)
        self._srp = SRPAuthHandler(
            '6fdad309-5331-47ff-b525-1158bb105af1'.encode())

        self._atv_remote = MrpRemoteControl(self)
        self._atv_metadata = MrpMetadata()
        self._atv_push_updater = MrpPushUpdater()
        self._atv_pairing = MrpPairingHandler(
            loop, self._connection, self._srp)
        self._airplay = airplay

    @asyncio.coroutine
    def login(self):
        """Perform an explicit login."""
        # TODO: This is hack-ish. Must refactor and fix better handling later.

        yield from self._connection.connect()
        message = messages.device_information(
            'pyatv', '6fdad309-5331-47ff-b525-1158bb105af1')
        self._connection.send(message)
        yield from self._connection.receive()

        # Verify credentials and generate keys
        credentials = Credentials.parse(self._service.device_credentials)
        print(credentials)
        pair_verifier = MrpPairingVerifier(
            self._connection, self._srp, credentials)

        yield from pair_verifier.verify_credentials()
        output_key, input_key = pair_verifier.encryption_keys()
        self._connection.enable_encryption(output_key, input_key)

        yield from self._send_messages()

    @asyncio.coroutine
    def _send_messages(self):
        self._connection.send(messages.client_updates_config())

        _LOGGER.debug("Waiting for messages...")
        recv = None
        while recv != b'':
            recv = yield from self._connection.receive()

    @asyncio.coroutine
    def logout(self):
        """Perform an explicit logout.

        Must be done when session is no longer needed to not leak resources.
        """
        self._session.close()

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
