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

import os
import sys
import binascii
import uuid
import asyncio
import hashlib
import curve25519

from pyatv.mrp.protobuf import ProtocolMessage_pb2 as PB
import pyatv.mrp.protobuf.DeviceInfoMessage_pb2 as DeviceInfoMessage
import pyatv.mrp.protobuf.CryptoPairingMessage_pb2 as CryptoPairingMessage
import pyatv.mrp.protobuf.ClientUpdatesConfigMessage_pb2 as ClientUpdatesConfigMessage
from pyatv.mrp.variant import read_variant, write_variant

from srptools import (SRPContext, SRPClientSession, constants)
from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305
from ed25519.keys import SigningKey, VerifyingKey

PORT = 51163 # Random each time simulator is started, should be discovered with zeroconf
HOST = '127.0.0.1'
PHONE_IDENTIFIER = '6fdad309-5331-47ff-b525-1158bb105af1'


# ------------------------------------------------------------------------------


def hkdf_expand(salt, info, shared_key):
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
    return hkdf.derive(shared_key)


# TODO: factories for messages are never a good idea, prefer builders
class MessageFactory:

    def __init__(self):
        self._session = str(uuid.uuid4()).upper()

    def make(self, type, priority=0, add_identifier=True):
        message = PB.ProtocolMessage()
        message.type = type
        if add_identifier:
            message.identifier = self._session
        message.priority = priority
        return message

    def crypto_pairing(self, tlv):
        message = self.make(PB.ProtocolMessage.CRYPTO_PAIRING_MESSAGE)
        crypto = message.Extensions[CryptoPairingMessage.cryptoPairingMessage]
        crypto.status = 0
        crypto.pairingData = tlv
        return message


class Chacha20Cipher:

    def __init__(self, in_key, out_key):
        self._enc_in = CHACHA20_POLY1305(in_key, 'python')
        self._enc_out = CHACHA20_POLY1305(out_key, 'python')
        self._out_counter = 0
        self._in_counter = 0

    def encrypt(self, data, nounce=None):
        if nounce is None:
            nounce = self._out_counter.to_bytes(length=8, byteorder='little')
            self._out_counter += 1

        return self._enc_out.seal(b'\x00\x00\x00\x00' + nounce, data, bytes())

    def decrypt(self, data, nounce=None):
        if nounce is None:
            nounce = self._in_counter.to_bytes(length=8, byteorder='little')
            self._in_counter += 1

        return self._enc_in.open(b'\x00\x00\x00\x00' + nounce, data, bytes())


# This is just a temporary hack to send and receive protobuf message. Will be
# replaced with something that handles incoming data more async-friendly. Also,
# use "real" logging later on.
class TempNetwork:

    def __init__(self, host, port, loop):
        self.host = str(host)  # TODO: which datatype do I want here?
        self.port = port
        self.loop = loop
        self._buffer = b''
        self._reader = None
        self._writer = None
        self._chacha = None

    def enable_encryption(self, c2a_key, a2c_key):
        # TODO: not sure which key is which here...
        self._chacha = Chacha20Cipher(a2c_key, c2a_key) #, a2c_key)

    @asyncio.coroutine
    def connect(self):
        print(str(self.host))
        print(self.port)
        self._reader, self._writer = yield from asyncio.open_connection(
            self.host, self.port, loop=self.loop)

    def close(self):
        self._writer.close()

    def send(self, message):
        serialized = message.SerializeToString()

        print('>> ({0}): '.format(len(serialized)) + ' '.join('{0:02X}'.format(i) for i in bytearray(serialized)))
        if self._chacha:
            serialized = binascii.unhexlify(b'08112000b201020800')
            serialized = self._chacha.encrypt(serialized)

        data = write_variant(len(serialized)) + serialized
        self._writer.write(data)
        print('>> ENCRYPTED ({0}): '.format(len(data)) + ' '.join('{0:02X}'.format(i) for i in bytearray(data)))
        print('>> ' + str(message))

    @asyncio.coroutine
    def receive(self):
        data = yield from self._reader.read(2048)
        if data == b'':  # TODO: handle better
            print("connection closed")
            return b''

        self._buffer += data
        print('<< ({0}): '.format(len(data)) + ' '.join('{0:02X}'.format(i) for i in bytearray(data)))

        length, raw = read_variant(self._buffer)

        # The variant tells us how much data must follow
        if len(raw) < length:
            print('require {0} bytes to decode, only have {1}'.format(length, len(raw)))
            return None

        data = raw[:length]  # Incoming message (might be encrypted)
        self._buffer = raw[length:]  # Buffer, might contain more messages

        if self._chacha:
            data = self._chacha.decrypt(data)  # TODO: not tested (concept)
            if not data:
                print("failed to decrypt")
                sys.exit(1)
            data = bytes(data)
            print('<< DECRYPTED ({0}): '.format(len(data)) + ' '.join('{0:02X}'.format(i) for i in bytearray(data)))

        print(data)
        parsed = PB.ProtocolMessage()
        parsed.ParseFromString(data)
        print('<< ' + str(parsed))
        return parsed


# ------------------------------------------------------------------------------

# This should be one module later

# Simple method to parse TLV data. If value is larger than 255 bytes, it is
# split up in multiple chunks. So the same tag might occurr several times.
def parse_tlv(data):
    def _parse(data, pos, size, result=None):
        if result is None:
            result = {}
        if pos >= size:
            return result

        tag = str(data[pos])
        len = data[pos+1]
        value = data[pos+2:pos+2+len]

        if tag in result:
            result[tag] += value  # value > 255 is split up
        else:
            result[tag] = value
        return _parse(data, pos+2+len, size, result)

    return _parse(data, 0, len(data))


def make_tlv(data):
    tlv = b''
    for key, value in data.items():
        tag = bytes([int(key)])
        length = len(value)
        pos = 0

        # A tag with length > 255 is added multiple times and concatenated into
        # one buffer when reading the TLV again.
        while pos < len(value):
            size = min(length, 255)
            tlv += tag
            tlv += bytes([size])
            tlv += value[pos:pos+size]
            pos += size
            length -= size
    return tlv


TLV_METHOD = '0'
TLV_IDENTIFIER = '1'
TLV_SALT = '2'
TLV_PUBLIC_KEY = '3'
TLV_PROOF = '4'
TLV_ENCRYPTED_DATA = '5'
TLV_SEQ_NO = '6'
TLV_BACK_OFF = '8'  # Time before a new pairing process can be started
TLV_SIGNATURE = '10'

# ------------------------------------------------------------------------------

# Helper method for now...
def pretty(name, value):
    print('{0}: {1} (len: {2})'.format(
            name, binascii.hexlify(bytearray(value)), len(value)))


@asyncio.coroutine
def device_information(net):
    print('Getting device information...')
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
    device_info = yield from net.receive()
    print('Device information: {0}'.format(device_info))


@asyncio.coroutine
def run(loop):
    net = TempNetwork(HOST, PORT, loop)
    yield from net.connect()

#     factory = MessageFactory()
#     pairing_id = PHONE_IDENTIFIER.encode()
#     yield from device_information(net)


#     atv_pub_key = binascii.unhexlify(b'c75a0a43e931e43a0c74da81b1388eef048bbaacdc0eec1a7e1a3bbb6e76daf2')
#     atv_identifier = binascii.unhexlify(b'39633731323036382d626238642d343262652d386364332d323164643463383362323430')
#     pairing_id = binascii.unhexlify(b'36666461643330392d353333312d343766662d623532352d313135386262313035616631')
#     ltsk = binascii.unhexlify(b'fc585c4929d6c8012092dbc572e354a3f82d28f4a115a4caf5026715fc52605e')

    # Uncomment and do pairing
    #atv_pub_key, atv_identifier, ltsk = yield from pair(net, factory, pairing_id)


    # Save return values from pair into variables above, comment out call to
    # pair and then verify should work without pairing again
    print('PUB Key:    ' + str(binascii.hexlify(atv_pub_key)))
    print('Identifier: ' + str(binascii.hexlify(atv_identifier)))
    print('Pairing:    ' + str(binascii.hexlify(pairing_id)))
    print('LTSK:       ' + str(binascii.hexlify(ltsk)))

    controller_to_accessory_key, accessory_to_controller_key = yield from verify(net, factory, atv_pub_key, atv_identifier, ltsk, pairing_id)

    net.enable_encryption(controller_to_accessory_key, accessory_to_controller_key)

    yield from send_messages(net, factory)

    net.close()

@asyncio.coroutine
def pair(net, factory, pairing_id):
    print('Initiate pairing process...')

    srp_signing_key = SigningKey(os.urandom(32))
    srp_verifying_key = srp_signing_key.get_verifying_key()
    srp_auth_private = srp_signing_key.to_seed()
    srp_auth_public = srp_verifying_key.to_bytes()

    # --------------------------------------------------

    tlv = make_tlv({TLV_METHOD: b'\x00', TLV_SEQ_NO: b'\x01'})
    net.send(factory.crypto_pairing(tlv))

    resp = yield from net.receive()
    pairing_data = parse_tlv(resp.Extensions[CryptoPairingMessage.cryptoPairingMessage].pairingData)

    if TLV_BACK_OFF in pairing_data:
        print('Retry in {}s'.format(int.from_bytes(pairing_data[TLV_BACK_OFF], byteorder='big')))
        sys.exit(1)

    atv_salt = pairing_data[TLV_SALT]
    atv_pub_key = pairing_data[TLV_PUBLIC_KEY]

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
        print('proofs do not match (mitm?)')
        sys.exit(1)

    pub_key = binascii.unhexlify(client_public)
    proof = binascii.unhexlify(client_session_key_proof)
    pretty('LOCAL KEY: ', pub_key)
    pretty('LOCAL PROOF: ', proof)

    print('Initiate pairing process...')
    tlv = make_tlv({TLV_SEQ_NO: b'\x03',
                    TLV_PUBLIC_KEY: pub_key,
                    TLV_PROOF: proof})
    net.send(factory.crypto_pairing(tlv))

    resp = yield from net.receive()
    pairing_data = parse_tlv(resp.Extensions[CryptoPairingMessage.cryptoPairingMessage].pairingData)
    atv_proof = pairing_data[TLV_PROOF]
    pretty('ATV Proof', atv_proof)

    srp_session_key = binascii.unhexlify(client_session_key)

    ios_device_x = hkdf_expand('Pair-Setup-Controller-Sign-Salt',
                               'Pair-Setup-Controller-Sign-Info',
                               srp_session_key)

    session_key = hkdf_expand('Pair-Setup-Encrypt-Salt',
                              'Pair-Setup-Encrypt-Info',
                              srp_session_key)

    device_info = ios_device_x + pairing_id + srp_auth_public
    device_signature = srp_signing_key.sign(device_info)

    tlv = make_tlv({TLV_IDENTIFIER: pairing_id,
                    TLV_PUBLIC_KEY: srp_auth_public,
                    TLV_SIGNATURE: device_signature})

    chacha = Chacha20Cipher(session_key, session_key)
    encrypted_data = chacha.encrypt(tlv, nounce='PS-Msg05'.encode())
    pretty('Encrypted data', encrypted_data)

    # --------------------------------------------------

    tlv = make_tlv({TLV_SEQ_NO: b'\x05', TLV_ENCRYPTED_DATA: encrypted_data})
    net.send(factory.crypto_pairing(tlv))

    resp = yield from net.receive()
    pairing_data = parse_tlv(resp.Extensions[CryptoPairingMessage.cryptoPairingMessage].pairingData)
    encrypted_data = pairing_data[TLV_ENCRYPTED_DATA]

    decrypted_tlv_bytes = chacha.decrypt(encrypted_data, nounce='PS-Msg06'.encode())
    if not decrypted_tlv_bytes:
        print('Failed to decrypt')
        sys.exit(1)
    decrypted_tlv = parse_tlv(decrypted_tlv_bytes)
    print('DECRYPTED: {0}'.format(decrypted_tlv))

    atv_identifier = decrypted_tlv[TLV_IDENTIFIER]
    atv_signature = decrypted_tlv[TLV_SIGNATURE]
    atv_pub_key = decrypted_tlv[TLV_PUBLIC_KEY]
    pretty('ATV identifier', atv_identifier)
    pretty('ATV signature', atv_signature)
    pretty('ATV public key', atv_pub_key)

    # TODO: verify signature here

    return atv_pub_key, atv_identifier, srp_signing_key.to_seed()


@asyncio.coroutine
def verify(net, factory, atv_pub_key, atv_identifier, ltsk, pairing_id):
    print('Verifying stuff and generating keys...')

    srp_verify_private = curve25519.Private(secret=os.urandom(32))
    srp_verify_public = srp_verify_private.get_public()

    tlv = make_tlv({TLV_SEQ_NO: b'\x01', TLV_PUBLIC_KEY: srp_verify_public.serialize()})
    net.send(factory.crypto_pairing(tlv))

    resp = yield from net.receive()
    resp = parse_tlv(resp.Extensions[CryptoPairingMessage.cryptoPairingMessage].pairingData)
    atv_session_pub_key = resp[TLV_PUBLIC_KEY]
    atv_encrypted = resp[TLV_ENCRYPTED_DATA]
    pretty('ATV Public key', atv_pub_key)
    pretty('ATV Encrypted',  atv_encrypted)

    public = curve25519.Public(atv_session_pub_key)
    shared = srp_verify_private.get_shared_key(
        public, hashfunc=lambda x: x)  # No additional hashing used

    session_key = hkdf_expand('Pair-Verify-Encrypt-Salt',
                              'Pair-Verify-Encrypt-Info',
                              shared)

    chacha = Chacha20Cipher(session_key, session_key)
    decrypted = chacha.decrypt(atv_encrypted, nounce='PV-Msg02'.encode())

    decrypted_tlv = parse_tlv(decrypted)

    identifier = decrypted_tlv[TLV_IDENTIFIER]
    signature = decrypted_tlv[TLV_SIGNATURE]

    if identifier != atv_identifier:
        print('Not correct device')
        sys.exit(1)

    info = atv_session_pub_key + bytes(identifier) + srp_verify_public.serialize()
    ltpk = VerifyingKey(bytes(atv_pub_key))
    ltpk.verify(bytes(signature), bytes(info))  # throws exception if no match

    device_info = srp_verify_public.serialize() + pairing_id + atv_session_pub_key

    signer = SigningKey(ltsk)
    device_signature = signer.sign(device_info)

    tlv = make_tlv({TLV_IDENTIFIER: pairing_id, TLV_SIGNATURE: device_signature})

    print("TLV: {0}".format(tlv))
    print("Decoded: {0}".format(parse_tlv(tlv)))
    chacha = Chacha20Cipher(session_key, session_key)
    encrypted_data = chacha.encrypt(tlv, nounce='PV-Msg03'.encode())

    tlv = make_tlv({TLV_SEQ_NO: b'\x03', TLV_ENCRYPTED_DATA: encrypted_data})
    net.send(factory.crypto_pairing(tlv))

    resp = yield from net.receive()
    pairing_data = parse_tlv(resp.Extensions[CryptoPairingMessage.cryptoPairingMessage].pairingData)
    # TODO: check status code

    controller_to_accessory_key = hkdf_expand('MediaRemote-Salt',
                                              'MediaRemote-Write-Encryption-Key',
                                              shared)

    accessory_to_controller_key = hkdf_expand('MediaRemote-Salt',
                                              'MediaRemote-Read-Encryption-Key',
                                              shared)

    pretty('CONTR->ACCES', controller_to_accessory_key)  # outputKey?
    pretty('ACCES->CONTR', accessory_to_controller_key)  # inputKey?

    return controller_to_accessory_key, accessory_to_controller_key


# Send some messages and try stuff out here...
@asyncio.coroutine
def send_messages(net, factory):
    print('Send some messages...')

#     message = factory.make(PB.ProtocolMessage.UNKNOWN_1, add_identifier=False)
#     message.temp.state = 2
#     net.send(message)

    message = factory.make(PB.ProtocolMessage.CLIENT_UPDATES_CONFIG_MESSAGE, add_identifier=False)
    config = message.Extensions[ClientUpdatesConfigMessage.clientUpdatesConfigMessage]
    config.artworkUpdates = True
    config.nowPlayingUpdates = True
    config.volumeUpdates = True
    config.keyboardUpdates = True
    net.send(message)

#     message = factory.make(PB.ProtocolMessage.GET_KEYBOARD_SESSION_MESSAGE, add_identifier=True)
#     message.keyboardSessionMessage.getKeyboardSessionMessage = "";
#     net.send(message)

    recv = None
    while recv != b'':
        recv = yield from net.receive()
