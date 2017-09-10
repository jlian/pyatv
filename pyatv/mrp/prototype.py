"""Prototype code for MRP."""

import binascii
import uuid
import asyncio
import logging

from pyatv.mrp import (tlv8, chacha20)
from pyatv.mrp.protobuf import ProtocolMessage_pb2 as PB
from pyatv.mrp.protobuf import DeviceInfoMessage_pb2 as DeviceInfoMessage
from pyatv.mrp.protobuf import CryptoPairingMessage_pb2 as CryptoPairingMessage
from pyatv.mrp.variant import (read_variant, write_variant)

_LOGGER = logging.getLogger(__name__)

PHONE_IDENTIFIER = '6fdad309-5331-47ff-b525-1158bb105af1'


# Special log method to avoid hexlify conversion if debug is off
def _log_debug(message, **kwargs):
    if _LOGGER.isEnabledFor(logging.DEBUG):
        output = ('{0}={1}'.format(k, binascii.hexlify(
            bytearray(v)).decode()) for k, v in kwargs.items())
        _LOGGER.debug('%s (%s)', message, ', '.join(output))


class MessageFactory:
    """Factory to create messages."""

    def __init__(self):
        """Initialize a new MessageFactory."""
        self._session = str(uuid.uuid4()).upper()

    def make(self, message_type, priority=0, add_identifier=True):
        """Create a new message."""
        message = PB.ProtocolMessage()
        message.type = message_type
        if add_identifier:
            message.identifier = self._session
        message.priority = priority
        return message

    def crypto_pairing(self, pairing_data):
        """Create a CryptoPairingMessage."""
        # pylint: disable=no-member
        message = self.make(PB.ProtocolMessage.CRYPTO_PAIRING_MESSAGE)
        # pylint: disable=no-member
        crypto = message.Extensions[CryptoPairingMessage.cryptoPairingMessage]
        crypto.status = 0
        crypto.pairingData = tlv8.write_tlv(pairing_data)
        return message


class MrpConnection:
    """Network layer that encryptes/decryptes and (de)serializes messages."""

    def __init__(self, host, port, loop):
        """Initialize a new MrpConnection."""
        self.host = str(host)  # TODO: which datatype do I want here?
        self.port = port
        self.loop = loop
        self._buffer = b''
        self._reader = None
        self._writer = None
        self._chacha = None

    def enable_encryption(self, output_key, input_key):
        """Enable encryption with the specified keys."""
        self._chacha = chacha20.Chacha20Cipher(output_key, input_key)

    @asyncio.coroutine
    def connect(self):
        """Connect to device."""
        self._reader, self._writer = yield from asyncio.open_connection(
            self.host, self.port, loop=self.loop)

    def close(self):
        """Close connection to device."""
        self._writer.close()

    def send(self, message):
        """Send message to device."""
        serialized = message.SerializeToString()

        _log_debug('>> Send', Data=serialized)
        if self._chacha:
            serialized = self._chacha.encrypt(serialized)
            _log_debug('>> Send', Encrypted=serialized)

        data = write_variant(len(serialized)) + serialized
        self._writer.write(data)
        _LOGGER.debug('>> Send: Protobuf=%s', message)

    @asyncio.coroutine
    def receive(self):
        """Receive message from device."""
        data = yield from self._reader.read(1024)
        if data == b'':
            _LOGGER.debug('Device closed the connection')
            return b''

        # A message might be split over several reads, so we store a buffer and
        # try to decode messages from that buffer
        self._buffer += data
        _log_debug('<< Receive', Data=data)

        # The variant tells us how much data must follow
        length, raw = read_variant(self._buffer)
        if len(raw) < length:
            _LOGGER.debug(
                'Require %d bytes but only %d in buffer', length, len(raw))
            return None

        data = raw[:length]  # Incoming message (might be encrypted)
        self._buffer = raw[length:]  # Buffer, might contain more messages

        if self._chacha:
            data = self._chacha.decrypt(data)
            _log_debug('<< Receive', Decrypted=data)

        parsed = PB.ProtocolMessage()
        parsed.ParseFromString(data)
        _LOGGER.debug('<< Receive: Protobuf=%s', parsed)
        return parsed


@asyncio.coroutine
def device_information(connection):
    """Exchange device information messages."""
    # pylint: disable=no-member
    message = MessageFactory().make(PB.ProtocolMessage.DEVICE_INFO_MESSAGE)
    # pylint: disable=no-member
    info = message.Extensions[DeviceInfoMessage.deviceInfoMessage]
    info.uniqueIdentifier = PHONE_IDENTIFIER
    info.name = 'pyatv'
    info.localizedModelName = 'iPhone'
    info.systemBuildVersion = '14G60'
    info.applicationBundleIdentifier = 'com.apple.TVRemote'
    info.applicationBundleVersion = '273.12'
    info.protocolVersion = 1

    connection.send(message)
    yield from connection.receive()


def _get_pairing_data(resp):
    pairing_message = CryptoPairingMessage.cryptoPairingMessage
    return tlv8.read_tlv(resp.Extensions[pairing_message].pairingData)


class MrpPairingHandler:
    """Perform pairing and return new credentials."""

    def __init__(self, factory, connection, srp):
        """Initialize a new MrpPairingHandler."""
        self.factory = factory
        self.connection = connection
        self.srp = srp
        self._atv_salt = None
        self._atv_pub_key = None

    @asyncio.coroutine
    def start_pairing(self):
        """Start pairing procedure."""
        self.srp.initialize()

        self.connection.send(self.factory.crypto_pairing(
            {tlv8.TLV_METHOD: b'\x00', tlv8.TLV_SEQ_NO: b'\x01'}))

        resp = yield from self.connection.receive()
        pairing_data = _get_pairing_data(resp)

        if tlv8.TLV_BACK_OFF in pairing_data:
            time = int.from_bytes(
                pairing_data[tlv8.TLV_BACK_OFF], byteorder='big')
            raise Exception('back off {0}s'.format(time))

        self._atv_salt = pairing_data[tlv8.TLV_SALT]
        self._atv_pub_key = pairing_data[tlv8.TLV_PUBLIC_KEY]

    @asyncio.coroutine
    def finish_pairing(self, pin):
        """Finish pairing process."""
        self.srp.step1(pin)

        pub_key, proof = self.srp.step2(self._atv_pub_key, self._atv_salt)
        self.connection.send(self.factory.crypto_pairing(
            {tlv8.TLV_SEQ_NO: b'\x03',
             tlv8.TLV_PUBLIC_KEY: pub_key,
             tlv8.TLV_PROOF: proof}))

        resp = yield from self.connection.receive()
        pairing_data = _get_pairing_data(resp)
        atv_proof = pairing_data[tlv8.TLV_PROOF]
        _log_debug('Device', Proof=atv_proof)

        encrypted_data = self.srp.step3()
        self.connection.send(self.factory.crypto_pairing({
            tlv8.TLV_SEQ_NO: b'\x05',
            tlv8.TLV_ENCRYPTED_DATA: encrypted_data}))

        resp = yield from self.connection.receive()
        pairing_data = _get_pairing_data(resp)
        encrypted_data = pairing_data[tlv8.TLV_ENCRYPTED_DATA]

        return self.srp.step4(encrypted_data)


class MrpPairingVerifier:
    """Verify credentials and derive new encryption keys."""

    def __init__(self, connection, srp, factory, pairing_details):
        """Initialize a new MrpPairingVerifier."""
        self.connection = connection
        self.srp = srp
        self.factory = factory
        self.details = pairing_details
        self._output_key = None
        self._input_key = None

    @asyncio.coroutine
    def verify_credentials(self):
        """Verify credentials with device."""
        _, public_key = self.srp.initialize()

        self.connection.send(self.factory.crypto_pairing({
            tlv8.TLV_SEQ_NO: b'\x01',
            tlv8.TLV_PUBLIC_KEY: public_key}))

        resp = yield from self.connection.receive()
        resp = _get_pairing_data(resp)
        atv_session_pub_key = resp[tlv8.TLV_PUBLIC_KEY]
        atv_encrypted = resp[tlv8.TLV_ENCRYPTED_DATA]
        _log_debug('Device', Public=self.details.ltpk, Encrypted=atv_encrypted)

        encrypted_data = self.srp.verify1(
            self.details.ltpk, atv_session_pub_key, self.details.atv_id,
            atv_encrypted, self.details.ltsk)
        self.connection.send(self.factory.crypto_pairing({
            tlv8.TLV_SEQ_NO: b'\x03',
            tlv8.TLV_ENCRYPTED_DATA: encrypted_data}))

        resp = yield from self.connection.receive()
        # TODO: check status code

        self._output_key, self._input_key = self.srp.verify2()

    def encryption_keys(self):
        """Return derived encryption keys."""
        return self._output_key, self._input_key
