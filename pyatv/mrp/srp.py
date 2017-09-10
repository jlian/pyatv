"""Prototype code for MRP."""

import os
import binascii
import hashlib
import logging

from collections import namedtuple

import curve25519

from pyatv import exceptions
from pyatv.mrp import (tlv8, chacha20)

from srptools import (SRPContext, SRPClientSession, constants)
from ed25519.keys import SigningKey, VerifyingKey

_LOGGER = logging.getLogger(__name__)

PairingDetails = namedtuple('PairingDetails', 'ltpk ltsk atv_id client_id')


# Special log method to avoid hexlify conversion if debug is off
def _log_debug(message, **kwargs):
    if _LOGGER.isEnabledFor(logging.DEBUG):
        output = ('{0}={1}'.format(k, binascii.hexlify(
            bytearray(v)).decode()) for k, v in kwargs.items())
        _LOGGER.debug('%s (%s)', message, ', '.join(output))


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


class SRPAuthHandler:
    """Handle SRP crypto routines for auth and key derivation."""

    def __init__(self, pairing_id):
        """Initialize a new SRPAuthHandler."""
        self.pairing_id = pairing_id
        self._signing_key = None
        self._auth_private = None
        self._auth_public = None
        self._verify_private = None
        self._verify_public = None
        self._session = None
        self._shared = None
        self._session_key = None
        self._client_session_key = None  # TODO: can remove?

    def initialize(self):
        """Initialize operation by generating new keys."""
        self._signing_key = SigningKey(os.urandom(32))
        self._auth_private = self._signing_key.to_seed()
        self._auth_public = self._signing_key.get_verifying_key().to_bytes()
        self._verify_private = curve25519.Private(secret=os.urandom(32))
        self._verify_public = self._verify_private.get_public()
        return self._auth_public, self._verify_public.serialize()

    def verify1(self, atv_pub_key, atv_session_pub_key,
                atv_identifier, atv_encrypted, ltsk):
        """First verification step."""
        public = curve25519.Public(atv_session_pub_key)
        self._shared = self._verify_private.get_shared_key(
            public, hashfunc=lambda x: x)  # No additional hashing used

        session_key = hkdf_expand('Pair-Verify-Encrypt-Salt',
                                  'Pair-Verify-Encrypt-Info',
                                  self._shared)

        chacha = chacha20.Chacha20Cipher(session_key, session_key)
        decrypted = chacha.decrypt(atv_encrypted, nounce='PV-Msg02'.encode())

        decrypted_tlv = tlv8.read_tlv(decrypted)

        identifier = decrypted_tlv[tlv8.TLV_IDENTIFIER]
        signature = decrypted_tlv[tlv8.TLV_SIGNATURE]

        if identifier != atv_identifier:
            raise Exception('incorrect device response')  # TODO: new exception

        info = atv_session_pub_key + \
            bytes(identifier) + self._verify_public.serialize()
        ltpk = VerifyingKey(bytes(atv_pub_key))
        ltpk.verify(bytes(signature), bytes(info))  # throws if no match

        device_info = self._verify_public.serialize() + \
            self.pairing_id + atv_session_pub_key

        signer = SigningKey(ltsk)
        device_signature = signer.sign(device_info)

        tlv = tlv8.write_tlv({tlv8.TLV_IDENTIFIER: self.pairing_id,
                              tlv8.TLV_SIGNATURE: device_signature})

        return chacha.encrypt(tlv, nounce='PV-Msg03'.encode())

    def verify2(self):
        """Last verification step.

        The derived keys (output, input) are returned here.
        """
        output_key = hkdf_expand('MediaRemote-Salt',
                                 'MediaRemote-Write-Encryption-Key',
                                 self._shared)

        input_key = hkdf_expand('MediaRemote-Salt',
                                'MediaRemote-Read-Encryption-Key',
                                self._shared)

        _log_debug('Keys', Output=output_key, Input=input_key)
        return output_key, input_key

    def step1(self, pin):
        """First pairing step."""
        context = SRPContext(
            'Pair-Setup', str(pin),
            prime=constants.PRIME_3072,
            generator=constants.PRIME_3072_GEN,
            hash_func=hashlib.sha512)
        self._session = SRPClientSession(
            context, binascii.hexlify(self._auth_private).decode())

    def step2(self, atv_pub_key, atv_salt):
        """Second pairing step."""
        pk_str = binascii.hexlify(atv_pub_key).decode()
        salt = binascii.hexlify(atv_salt).decode()
        self._client_session_key, _, _ = self._session.process(pk_str, salt)

        if not self._session.verify_proof(self._session.key_proof_hash):
            raise exceptions.AuthenticationError('proofs do not match (mitm?)')

        pub_key = binascii.unhexlify(self._session.public)
        proof = binascii.unhexlify(self._session.key_proof)
        _log_debug('Client', Public=pub_key, Proof=proof)
        return pub_key, proof

    def step3(self):
        """Third pairing step."""
        ios_device_x = hkdf_expand(
            'Pair-Setup-Controller-Sign-Salt',
            'Pair-Setup-Controller-Sign-Info',
            binascii.unhexlify(self._client_session_key))

        self._session_key = hkdf_expand(
            'Pair-Setup-Encrypt-Salt',
            'Pair-Setup-Encrypt-Info',
            binascii.unhexlify(self._client_session_key))

        device_info = ios_device_x + self.pairing_id + self._auth_public
        device_signature = self._signing_key.sign(device_info)

        tlv = tlv8.write_tlv({tlv8.TLV_IDENTIFIER: self.pairing_id,
                              tlv8.TLV_PUBLIC_KEY: self._auth_public,
                              tlv8.TLV_SIGNATURE: device_signature})

        chacha = chacha20.Chacha20Cipher(self._session_key, self._session_key)
        encrypted_data = chacha.encrypt(tlv, nounce='PS-Msg05'.encode())
        _log_debug('Data', Encrypted=encrypted_data)
        return encrypted_data

    def step4(self, encrypted_data):
        """Last pairing step."""
        chacha = chacha20.Chacha20Cipher(self._session_key, self._session_key)
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

        return PairingDetails(atv_pub_key, self._signing_key.to_seed(),
                              atv_identifier, self.pairing_id)
