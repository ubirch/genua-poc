import base64
from datetime import datetime, timedelta
from logging import getLogger
from os import urandom
from uuid import UUID

import ed25519
from ed25519 import SigningKey
from jks import jks, AlgorithmIdentifier, rfc5208
from pyasn1.codec.ber import encoder

log = getLogger(__name__)

class UbirchProtocol(object):
    """
    The ubirch-protocol packages data into a protocol wrapper, taking care of signing data, chaining of signatures
    and verification of incoming messages.
    """

    ECC_ENCRYPTION_OID = (1, 2, 1, 3, 101, 112)

    def __init__(self, uuid: UUID, keystore_file: str, password: str) -> None:
        """Initialize the ubirch-protocol for the device with the given UUID."""
        super().__init__()
        self._uuid = uuid.hex
        self._ks_file = keystore_file
        self._ks_password = password
        self._load_or_create_keys()

    def _load_or_create_keys(self) -> None:
        """Load or create new crypto-keys. The keys are stored in a local key store."""
        if not self._uuid:
            raise Exception("missing UUID to load key from keystore")

        # try to load the keystore or create a new one
        try:
            self._ks = jks.KeyStore.load(self._ks_file, self._ks_password)
        except FileNotFoundError:
            log.warning("creating new key store: {}".format(self._ks_file))
            self._ks = jks.KeyStore.new("jks", [])

        # load the key
        if self._uuid in self._ks.private_keys:
            sk = self._ks.private_keys[self._uuid]
            self._signingKey = SigningKey(sk.pkey)
            log.info("loaded signing key for {}".format(self._uuid))
        else:
            self._signingKey, vk = ed25519.create_keypair(entropy=urandom)

            # encode the ED25519 private key as PKCS#8
            ed25519_algorithm_oid = self.ECC_ENCRYPTION_OID
            private_key_info = rfc5208.PrivateKeyInfo()
            private_key_info.setComponentByName('version', 'v1')

            a = AlgorithmIdentifier()
            a.setComponentByName('algorithm', ed25519_algorithm_oid)
            private_key_info.setComponentByName('privateKeyAlgorithm', a)
            private_key_info.setComponentByName('privateKey', self._signingKey.to_bytes())
            pkey_pkcs8 = encoder.encode(private_key_info)

            pke = jks.PrivateKeyEntry.new(alias=str(self._uuid), certs=[], key=pkey_pkcs8)
            self._ks.entries[self._uuid] = pke
            self._ks.save(self._ks_file, self._ks_password)
            log.info("created new signing key for {}".format(self._uuid))

    def pack_key_registration(self) -> bytes:
        now = datetime.utcnow()

        created = self._time_format(now)
        not_before = self._time_format(now)
        not_after = self._time_format(now + timedelta(days=365))

        pub_key_enc = bytes.decode(base64.b64encode(self._sk.get_verifying_key().to_bytes()))
        pub_key_info = {
            "hwDeviceId": self._serial,
            "pubKey": pub_key_enc,
            "pubKeyId": pub_key_enc,
            "algorithm": 'ECC_ED25519',
            "created": created,
            "validNotBefore": not_before,
            "validNotAfter": not_after
        }

        pub_key_info_enc = str.encode(json.dumps(pub_key_info, sort_keys=True, separators=(',', ':')))
        signature = bytes.decode(base64.b64encode(self._sk.sign(pub_key_info_enc)))

        payload = {
            "pubKeyInfo": pub_key_info,
            "signature": signature
        }

        return str.encode(json.dumps(payload, sort_keys=True, separators={',', ":"}))
