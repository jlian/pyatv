# DISCLAIMER!!! This is a prototype and does not properly work! Use with care!
#
# Good to have: http://yura415.github.io/js-protobuf-encode-decode/
#
# Things to do:
# 1. Update PORT and HOST with correct details
# 2. Pair by calling pair(...) in run()
# 3. Save the identifiers (public key, identifier, pairing, ltsk)
# 4. Fill variables in run() with the saved identifiers
# 5. Comment out call to pair(...) as that is no longer needed
"""Prototype code for MRP."""

import os
import binascii
import uuid
import asyncio
import hashlib
import curve25519
import logging

from pyatv import exceptions
from .protobuf import ProtocolMessage_pb2 as PB
from .protobuf import DeviceInfoMessage_pb2 as DeviceInfoMessage
from .protobuf import CryptoPairingMessage_pb2 as CryptoPairingMessage
from .protobuf import ClientUpdatesConfigMessage_pb2 as ClientUpdates
from pyatv.mrp.variant import (read_variant, write_variant)
from pyatv.mrp import tlv8

from srptools import (SRPContext, SRPClientSession, constants)
from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305
from ed25519.keys import SigningKey, VerifyingKey

_LOGGER = logging.getLogger(__name__)

PHONE_IDENTIFIER = '6fdad309-5331-47ff-b525-1158bb105af1'


# Special log method to avoid hexlify conversion if debug is off
def _log_debug(message, **kwargs):
    if _LOGGER.isEnabledFor(logging.DEBUG):
        output = ('{0}={1}'.format(k, binascii.hexlify(
            bytearray(v)).decode()) for k, v in kwargs.items())
        _LOGGER.debug('%s (%s)', message, ', '.join(output))


# ------------------------------------------------------------------------------


def hkdf_expand(salt, info, shared_secret):
    """Dervice encryption keys from shared secret."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt.encode(),
        info=info.encode(),
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)


# TODO: factories for messages are never a good idea, prefer builders
class MessageFactory:
    """Factory to create messages."""

    def __init__(self):
        """Initialize a new MessageFactory."""
        self._session = str(uuid.uuid4()).upper()

    def make(self, type, priority=0, add_identifier=True):
        """Create a new message."""
        message = PB.ProtocolMessage()
        message.type = type
        if add_identifier:
            message.identifier = self._session
        message.priority = priority
        return message

    def crypto_pairing(self, tlv):
        """Create a CryptoPairingMessage."""
        message = self.make(PB.ProtocolMessage.CRYPTO_PAIRING_MESSAGE)
        crypto = message.Extensions[CryptoPairingMessage.cryptoPairingMessage]
        crypto.status = 0
        crypto.pairingData = tlv
        return message


class Chacha20Cipher:
    """CHACHA20 encryption/decryption layer."""

    def __init__(self, out_key, in_key):
        """Initialize a new Chacha20Cipher."""
        self._enc_out = CHACHA20_POLY1305(out_key, 'python')
        self._enc_in = CHACHA20_POLY1305(in_key, 'python')
        self._out_counter = 0
        self._in_counter = 0

    def encrypt(self, data, nounce=None):
        """Encrypt data with counter or specified nounce."""
        if nounce is None:
            nounce = self._out_counter.to_bytes(length=8, byteorder='little')
            self._out_counter += 1

        return self._enc_out.seal(b'\x00\x00\x00\x00' + nounce, data, bytes())

    def decrypt(self, data, nounce=None):
        """Decrypt data with counter or specified nounce."""
        if nounce is None:
            nounce = self._in_counter.to_bytes(length=8, byteorder='little')
            self._in_counter += 1

        decrypted = self._enc_in.open(
            b'\x00\x00\x00\x00' + nounce, data, bytes())

        if not decrypted:
            raise Exception('data decrypt failed')  # TODO: new exception

        return bytes(decrypted)


# This is just a temporary hack to send and receive protobuf message. Will be
# replaced with something that handles incoming data more async-friendly. Also,
# use "real" logging later on.
class TempNetwork:
    """Network layer that encryptes/decryptes and (de)serializes messages."""

    def __init__(self, host, port, loop):
        """Initialize a new TempNetwork."""
        self.host = str(host)  # TODO: which datatype do I want here?
        self.port = port
        self.loop = loop
        self._buffer = b''
        self._reader = None
        self._writer = None
        self._chacha = None

    def enable_encryption(self, output_key, input_key):
        """Enable encryption with the specified keys."""
        self._chacha = Chacha20Cipher(output_key, input_key)

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
def device_information(net):
    """Exchange device information messages."""
    message = MessageFactory().make(PB.ProtocolMessage.DEVICE_INFO_MESSAGE)
    info = message.Extensions[DeviceInfoMessage.deviceInfoMessage]
    info.uniqueIdentifier = PHONE_IDENTIFIER
    info.name = 'pyatv'
    info.localizedModelName = 'iPhone'
    info.systemBuildVersion = '14G60'
    info.applicationBundleIdentifier = 'com.apple.TVRemote'
    info.applicationBundleVersion = '273.12'
    info.protocolVersion = 1

    net.send(message)
    yield from net.receive()


@asyncio.coroutine
def pair(net, factory, pairing_id):
    """Start pairing with device."""
    srp_signing_key = SigningKey(os.urandom(32))
    srp_verifying_key = srp_signing_key.get_verifying_key()
    srp_auth_private = srp_signing_key.to_seed()
    srp_auth_public = srp_verifying_key.to_bytes()

    # --------------------------------------------------

    tlv = tlv8.write_tlv({tlv8.TLV_METHOD: b'\x00', tlv8.TLV_SEQ_NO: b'\x01'})
    net.send(factory.crypto_pairing(tlv))

    resp = yield from net.receive()
    pairing_data = tlv8.read_tlv(
        resp.Extensions[CryptoPairingMessage.cryptoPairingMessage].pairingData)

    if tlv8.TLV_BACK_OFF in pairing_data:
        time = int.from_bytes(
            pairing_data[tlv8.TLV_BACK_OFF], byteorder='big')
        raise Exception('back off {0}s'.format(time))

    atv_salt = pairing_data[tlv8.TLV_SALT]
    atv_pub_key = pairing_data[tlv8.TLV_PUBLIC_KEY]

    # --------------------------------------------------

    pin = input('PIN Code:')

    context = SRPContext(
        'Pair-Setup', str(pin),
        prime=constants.PRIME_3072,
        generator=constants.PRIME_3072_GEN,
        hash_func=hashlib.sha512)
    srp_session = SRPClientSession(
        context, binascii.hexlify(srp_auth_private).decode())

    # --------------------------------------------------

    pk_str = binascii.hexlify(atv_pub_key).decode()
    salt = binascii.hexlify(atv_salt).decode()
    client_session_key, _, _ = srp_session.process(pk_str, salt)

    # Generate client public and session key proof.
    client_public = srp_session.public
    client_session_key_proof = srp_session.key_proof

    if not srp_session.verify_proof(srp_session.key_proof_hash):
        raise exceptions.AuthenticationError('proofs do not match (mitm?)')

    pub_key = binascii.unhexlify(client_public)
    proof = binascii.unhexlify(client_session_key_proof)
    _log_debug('Client', Public=pub_key, Proof=proof)

    tlv = tlv8.write_tlv({tlv8.TLV_SEQ_NO: b'\x03',
                          tlv8.TLV_PUBLIC_KEY: pub_key,
                          tlv8.TLV_PROOF: proof})
    net.send(factory.crypto_pairing(tlv))

    resp = yield from net.receive()
    pairing_data = tlv8.read_tlv(
        resp.Extensions[CryptoPairingMessage.cryptoPairingMessage].pairingData)
    atv_proof = pairing_data[tlv8.TLV_PROOF]
    _log_debug('Device', Proof=atv_proof)

    srp_session_key = binascii.unhexlify(client_session_key)

    ios_device_x = hkdf_expand('Pair-Setup-Controller-Sign-Salt',
                               'Pair-Setup-Controller-Sign-Info',
                               srp_session_key)

    session_key = hkdf_expand('Pair-Setup-Encrypt-Salt',
                              'Pair-Setup-Encrypt-Info',
                              srp_session_key)

    device_info = ios_device_x + pairing_id + srp_auth_public
    device_signature = srp_signing_key.sign(device_info)

    tlv = tlv8.write_tlv({tlv8.TLV_IDENTIFIER: pairing_id,
                          tlv8.TLV_PUBLIC_KEY: srp_auth_public,
                          tlv8.TLV_SIGNATURE: device_signature})

    chacha = Chacha20Cipher(session_key, session_key)
    encrypted_data = chacha.encrypt(tlv, nounce='PS-Msg05'.encode())
    _log_debug('Data', Encrypted=encrypted_data)

    # --------------------------------------------------

    tlv = tlv8.write_tlv({tlv8.TLV_SEQ_NO: b'\x05',
                          tlv8.TLV_ENCRYPTED_DATA: encrypted_data})
    net.send(factory.crypto_pairing(tlv))

    resp = yield from net.receive()
    pairing_data = tlv8.read_tlv(
        resp.Extensions[CryptoPairingMessage.cryptoPairingMessage].pairingData)
    encrypted_data = pairing_data[tlv8.TLV_ENCRYPTED_DATA]

    decrypted_tlv_bytes = chacha.decrypt(
        encrypted_data, nounce='PS-Msg06'.encode())
    if not decrypted_tlv_bytes:
        raise Exception('data decrypt failed')  # TODO: new exception
    decrypted_tlv = tlv8.read_tlv(decrypted_tlv_bytes)
    _LOGGER.debug('PS-Msg06: %s', decrypted_tlv)

    atv_identifier = decrypted_tlv[tlv8.TLV_IDENTIFIER]
    atv_signature = decrypted_tlv[tlv8.TLV_SIGNATURE]
    atv_pub_key = decrypted_tlv[tlv8.TLV_PUBLIC_KEY]
    _log_debug('Device',
               Identifier=atv_identifier,
               Signature=atv_signature,
               Public=atv_pub_key)

    # TODO: verify signature here

    return atv_pub_key, atv_identifier, srp_signing_key.to_seed()


@asyncio.coroutine
def verify(net, factory, atv_pub_key, atv_identifier, ltsk, pairing_id):
    """Verify credentials and derive new session keys."""
    srp_verify_private = curve25519.Private(secret=os.urandom(32))
    srp_verify_public = srp_verify_private.get_public()

    tlv = tlv8.write_tlv({tlv8.TLV_SEQ_NO: b'\x01',
                          tlv8.TLV_PUBLIC_KEY: srp_verify_public.serialize()})
    net.send(factory.crypto_pairing(tlv))

    resp = yield from net.receive()
    resp = tlv8.read_tlv(
        resp.Extensions[CryptoPairingMessage.cryptoPairingMessage].pairingData)
    atv_session_pub_key = resp[tlv8.TLV_PUBLIC_KEY]
    atv_encrypted = resp[tlv8.TLV_ENCRYPTED_DATA]
    _log_debug('Device', Public=atv_pub_key, Encrypted=atv_encrypted)

    public = curve25519.Public(atv_session_pub_key)
    shared = srp_verify_private.get_shared_key(
        public, hashfunc=lambda x: x)  # No additional hashing used

    session_key = hkdf_expand('Pair-Verify-Encrypt-Salt',
                              'Pair-Verify-Encrypt-Info',
                              shared)

    chacha = Chacha20Cipher(session_key, session_key)
    decrypted = chacha.decrypt(atv_encrypted, nounce='PV-Msg02'.encode())

    decrypted_tlv = tlv8.read_tlv(decrypted)

    identifier = decrypted_tlv[tlv8.TLV_IDENTIFIER]
    signature = decrypted_tlv[tlv8.TLV_SIGNATURE]

    if identifier != atv_identifier:
        raise Exception('incorrect device response')  # TODO: new exception

    info = atv_session_pub_key + \
        bytes(identifier) + srp_verify_public.serialize()
    ltpk = VerifyingKey(bytes(atv_pub_key))
    ltpk.verify(bytes(signature), bytes(info))  # throws exception if no match

    device_info = srp_verify_public.serialize() + \
        pairing_id + atv_session_pub_key

    signer = SigningKey(ltsk)
    device_signature = signer.sign(device_info)

    tlv = tlv8.write_tlv({tlv8.TLV_IDENTIFIER: pairing_id,
                          tlv8.TLV_SIGNATURE: device_signature})

    print("TLV: {0}".format(tlv))
    print("Decoded: {0}".format(tlv8.read_tlv(tlv)))
    chacha = Chacha20Cipher(session_key, session_key)
    encrypted_data = chacha.encrypt(tlv, nounce='PV-Msg03'.encode())

    tlv = tlv8.write_tlv({tlv8.TLV_SEQ_NO: b'\x03',
                          tlv8.TLV_ENCRYPTED_DATA: encrypted_data})
    net.send(factory.crypto_pairing(tlv))

    resp = yield from net.receive()
#     pairing_data = tlv8.read_tlv(
#         resp.Extensions[CryptoPairingMessage.cryptoPairingMessage].pairingData)
    # TODO: check status code

    output_key = hkdf_expand('MediaRemote-Salt',
                             'MediaRemote-Write-Encryption-Key',
                             shared)

    input_key = hkdf_expand('MediaRemote-Salt',
                            'MediaRemote-Read-Encryption-Key',
                            shared)

    _log_debug('Keys', Output=output_key, Input=input_key)

    return output_key, input_key


# Send some messages and try stuff out here...
@asyncio.coroutine
def send_messages(net, factory):
    """Send some messages and try things out."""
#     message = factory.make(
#         PB.ProtocolMessage.UNKNOWN_1, add_identifier=False)
#     message.temp.state = 2
#     net.send(message)

    message = factory.make(
        PB.ProtocolMessage.CLIENT_UPDATES_CONFIG_MESSAGE,
        add_identifier=False)
    config = message.Extensions[ClientUpdates.clientUpdatesConfigMessage]
    config.artworkUpdates = True
    config.nowPlayingUpdates = True
    config.volumeUpdates = True
    config.keyboardUpdates = True
    net.send(message)

#     message = factory.make(
#         PB.ProtocolMessage.GET_KEYBOARD_SESSION_MESSAGE,
#         add_identifier=True)
#     message.keyboardSessionMessage.getKeyboardSessionMessage = "";
#     net.send(message)

    recv = None
    while recv != b'':
        recv = yield from net.receive()
