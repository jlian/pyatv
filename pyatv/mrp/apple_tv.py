"""Implementation of the MediaRemoteTV Protocol used by ATV4 and later."""

import uuid
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

    def __init__(self, loop, protocol):
        """Initialize a new MrpRemoteControl."""
        self.loop = loop
        self.protocol = protocol

    @asyncio.coroutine
    def stop(self):
        """Press key stop."""
        # TODO: just some sample code at the moment
        yield from self.protocol.send(messages.client_updates_config())
        yield from asyncio.sleep(100, loop=self.loop)


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

    def __init__(self, loop, protocol, srp, service):
        """Initialize a new MrpPairingHandler."""
        self.pairing_procedure = MrpPairingProcedure(protocol, srp)
        self.service = service

    @property
    def has_paired(self):
        """If a successful pairing has been performed."""
        return self.service.device_credentials is not None

    @asyncio.coroutine
    def start(self, **kwargs):
        """Start pairing process."""
        yield from self.pairing_procedure.start_pairing()

    @asyncio.coroutine
    def stop(self, **kwargs):
        """Stop pairing process."""
        pin = kwargs['pin']

        self.service.device_credentials = \
            yield from self.pairing_procedure.finish_pairing(pin)

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
        if key == 'credentials' and self.service.device_credentials:
            return str(self.service.device_credentials)


class MrpProtocol(object):
    """Protocol logic related to MRP.

    This class wraps an MrpConnection instance and will automatically:
    * Connect whenever it is needed
    * Send necessary messages automatically, e.g. DEVICE_INFORMATION
    * Enable encryption at the right time

    It provides an API for sending and receiving messages.
    """

    def __init__(self, loop, connection, srp, service):
        """Initialize a new MrpProtocol."""
        self.loop = loop
        self.connection = connection
        self.srp = srp
        self.service = service
        self._outstanding = {}
        self._future = None
        self._initial_message_sent = False

    @asyncio.coroutine
    def start(self):
        """Connect to device and listen to incoming messages."""
        yield from self.connection.connect()

        # TODO: refactor and share code with dmap.apple_tv.DmapPushUpdater
        if hasattr(asyncio, 'ensure_future'):
            run_async = getattr(asyncio, 'ensure_future')
        else:
            run_async = asyncio.async  # pylint: disable=no-member

        self._future = run_async(self._receiver(), loop=self.loop)

        # In case credentials have been given externally (i.e. not by pairing
        # with a device), then use that client id
        if self.service.device_credentials:
            self.srp.pairing_id = Credentials.parse(
                self.service.device_credentials).client_id

        # The first message must always be DEVICE_INFORMATION, otherwise the
        # device will not respond with anything
        msg = messages.device_information(
            'pyatv', self.srp.pairing_id.decode())
        yield from self.send_and_receive(msg)

        self._initial_message_sent = True

    def stop(self):
        """Disconnect from device."""
        if len(self._outstanding) > 0:
            _LOGGER.warning('There were %d outstanding requests',
                            len(self._outstanding))

        if self._future is not None:
            self._future.cancel()
            self._future = None
            self._enable_encryption = False
            self._initial_message_sent = False
            self._outstanding = {}

        self.connection.close()

    @asyncio.coroutine
    def _connect_and_encrypt(self):
        if not self.connection.connected:
            yield from self.start()

        # Encryption can be enabled whenever credentials are available but only
        # after DEVICE_INFORMATION has been sent
        if self.service.device_credentials and self._initial_message_sent:
            self._initial_message_sent = False

            # Verify credentials and generate keys
            credentials = Credentials.parse(self.service.device_credentials)
            pair_verifier = MrpPairingVerifier(self, self.srp, credentials)

            yield from pair_verifier.verify_credentials()
            output_key, input_key = pair_verifier.encryption_keys()
            self.connection.enable_encryption(output_key, input_key)

    @asyncio.coroutine
    def send(self, message):
        """Send a message and expect no response."""
        yield from self._connect_and_encrypt()
        self.connection.send(message)

    @asyncio.coroutine
    def send_and_receive(self, message, generate_identifier=True, timeout=5):
        """Send a message and wait for a response."""
        yield from self._connect_and_encrypt()

        # Some messages will respond with the same identifier as used in the
        # corresponding request. Others will not and one example is the crypto
        # message (for pairing). They will never include an identifer, but it
        # it is in turn only possible to have one of those message outstanding
        # at one time (i.e. it's not possible to mix up the responses). In
        # those cases, a "fake" identifier is used that includes the message
        # type instead.
        if generate_identifier:
            identifier = str(uuid.uuid4())
            message.identifier = identifier
        else:
            identifier = 'type_' + str(message.type)

        self.connection.send(message)
        return (yield from self._receive(identifier, timeout))

    @asyncio.coroutine
    def _receive(self, identifier, timeout):
        semaphore = asyncio.Semaphore(value=0, loop=self.loop)
        self._outstanding[identifier] = [semaphore, None]

        try:
            # The background "future" will save the response and release the
            # semaphore when it has been received
            yield from asyncio.wait_for(
                semaphore.acquire(), timeout, loop=self.loop)

        except:
            del self._outstanding[identifier]
            raise

        response = self._outstanding[identifier][1]
        del self._outstanding[identifier]
        return response

    @asyncio.coroutine
    def _receiver(self):
        _LOGGER.debug('MRP message receiver started')

        while True:
            try:
                _LOGGER.debug('Waiting for new message...')
                resp = yield from self.connection.receive()

                if not resp:
                    continue  # Only partial message received
                elif resp.identifier:
                    identifier = resp.identifier
                else:
                    identifier = 'type_' + str(resp.type)

                # If the message identifer is outstanding, then someone is
                # waiting for the respone so we ave it here
                if identifier in self._outstanding:
                    self._outstanding[identifier][1] = resp
                    self._outstanding[identifier][0].release()

            except asyncio.CancelledError:
                break


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
        self._srp = SRPAuthHandler()
        self._protocol = MrpProtocol(
            loop, self._connection, self._srp, self._service)

        self._atv_remote = MrpRemoteControl(loop, self._protocol)
        self._atv_metadata = MrpMetadata()
        self._atv_push_updater = MrpPushUpdater()
        self._atv_pairing = MrpPairingHandler(
            loop, self._protocol, self._srp, self._service)
        self._airplay = airplay

    @asyncio.coroutine
    def login(self):
        """Perform an explicit login."""
        # TODO: should not be here
        yield from self._protocol.send(messages.client_updates_config())

    @asyncio.coroutine
    def logout(self):
        """Perform an explicit logout.

        Must be done when session is no longer needed to not leak resources.
        """
        self._session.close()
        self._protocol.stop()

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
