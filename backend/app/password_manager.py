from typing import Optional, Tuple

from .utils import dict_to_json_str, json_str_to_dict
from .utils import str_to_bytes, bytes_to_str, encode_bytes, decode_bytes

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# number of iterations for PBKDF2 algorithm
PBKDF2_ITERATIONS = 100000
# we can assume no password is longer than this many characters
MAX_PASSWORD_LENGTH = 64

# Constants for key derivation
DOMAIN_HMAC_KEY_INDEX = b'domain'
PASSWORD_AES_KEY_INDEX = b'password'

class Keychain:
    curversion = 1  

    def __init__(
        self,
        masterkey: bytes,
        kvs=None, 
        salt=None,
        version: int = None 
    ):
        """
        Initializes the keychain using the provided information.
        """
        self._masterkey = masterkey
        self._version = version if version is not None else Keychain.curversion  

        self.data = {
            "kvs": kvs if kvs is not None else {},
        }
        self.secrets = {
            "salt": salt if salt is not None else get_random_bytes(16),
            "domain_hmac_key": HMAC.new(masterkey, DOMAIN_HMAC_KEY_INDEX, SHA256).digest(),
            "password_aes_key": HMAC.new(masterkey, PASSWORD_AES_KEY_INDEX, SHA256).digest(), 
            "auth_key": HMAC.new(masterkey, b"auth", digestmod=SHA256).digest()
        }

    @staticmethod
    def new(keychain_password: str) -> "Keychain":
        """Creates an empty keychain with the given keychain password."""
        salt = get_random_bytes(16)  
        masterkey = PBKDF2(keychain_password.encode('utf-8'), salt, PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
        return Keychain(masterkey, salt=salt)

    @staticmethod
    def load(
        keychain_password: str, repr: str, trusted_data_check: Optional[bytes] = None
    ) -> "Keychain":
        """Creates a new keychain from an existing key-value store."""
        data = json_str_to_dict(repr)

        # Check for previous version with checksum
        if trusted_data_check is not None:
            repr_bytes = str_to_bytes(repr)
            sha256 = SHA256.new()
            sha256.update(repr_bytes)
            checksum_repr = sha256.digest()

            if trusted_data_check != checksum_repr:
                raise ValueError("Checksum verification failed: tampered data")

        # Get stored version
        stored_version = data.get("version", 0)  

        # Ensure the stored version is not greater than the current version
        if stored_version < Keychain.curversion:
            raise ValueError("Rollback attack detected")

        master_key = PBKDF2(keychain_password.encode('utf-8'), decode_bytes(data["salt"]), PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
        
        # Check if tampered with verifier
        auth_key = decode_bytes(data["auth_key"])
        hmac_auth_key = HMAC.new(master_key, b"auth", digestmod=SHA256)
        hmac_auth_key.verify(auth_key)  

        return Keychain(master_key, data["kvs"], decode_bytes(data["salt"]), stored_version)

    def dump(self) -> Tuple[str, bytes]:
        """Returns a JSON serialization and a checksum of the contents."""
        Keychain.curversion += 1 
        self._version = Keychain.curversion  
        storage = {
            "salt": encode_bytes(self.secrets["salt"]),
            "kvs": self.data["kvs"],
            "auth_key": encode_bytes(self.secrets["auth_key"]), 
            "version": self._version 
        }
        
        ser = dict_to_json_str(storage)
        checksum = SHA256.new(str_to_bytes(ser)).digest()
        return ser, checksum

    def get(self, domain: str) -> Optional[str]:
        """Fetches the password for a given domain."""
        domain_hmac = HMAC.new(self.secrets["domain_hmac_key"], domain.encode("utf-8"), SHA256).digest()
        domainkey = encode_bytes(domain_hmac)

        if domainkey in self.data["kvs"]:
            encrypted_data = self.data["kvs"][domainkey]
            iv = decode_bytes(encrypted_data["iv"])
            ct = decode_bytes(encrypted_data["ct"])
            tag = decode_bytes(encrypted_data["tag"])

            aes = AES.new(self.secrets["password_aes_key"], AES.MODE_GCM, nonce=iv)
            aes.update(domain.encode("utf-8"))
            decrypted_password = aes.decrypt_and_verify(ct, tag)
            return decrypted_password.rstrip(b'\x00').decode('utf-8')
        
        return None

    def set(self, domain: str, password: str):
        """Sets or updates a password for a domain."""
        domain_hmac = HMAC.new(self.secrets["domain_hmac_key"], domain.encode("utf-8"), SHA256).digest()
        domainkey = encode_bytes(domain_hmac)
        padded_password = password.encode('utf-8').ljust(MAX_PASSWORD_LENGTH, b'\x00')

        iv = get_random_bytes(16)
        aes = AES.new(self.secrets["password_aes_key"], AES.MODE_GCM, nonce=iv)
        aes.update(domain.encode("utf-8"))
        ct, tag = aes.encrypt_and_digest(padded_password)

        self.data["kvs"][domainkey] = {
            "ct": encode_bytes(ct),
            "tag": encode_bytes(tag),
            "iv": encode_bytes(iv)
        }

    def remove(self, domain: str) -> bool:
        """Removes a domain-password pair."""
        domain_hmac = HMAC.new(self.secrets["domain_hmac_key"], domain.encode("utf-8"), SHA256).digest()
        domainkey = encode_bytes(domain_hmac)

        if domainkey in self.data["kvs"]:
            self.data["kvs"].pop(domainkey)
            return True
        
        return False 