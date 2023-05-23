""" Encrypt files and directories for backup on untrusted storage"""
import os

import base64
import logging

# pylint: disable=logging-fstring-interpolation

# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SCRYPT_N = 2**14
BUFFER_SIZE_BYTES = 32 * 1024 * 1024
IV_SIZE_BYTES = 12
TAG_SIZE_BYTES = 16
SALT_SIZE_BYTES = 16

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

_KEYSTORE = {}  # cached keys for detected salts


class EncryptionKey:
    """Encryption key with all data needed to derive it back from password"""

    def __init__(self, password: str, salt: bytes | None = None):
        """
        Generate new key wit optional salt
        If salt is not provided, it will be generated. It must be provided
        for successful decryption with previously generated key.
        """
        if salt is None:
            salt = os.urandom(SALT_SIZE_BYTES)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=SCRYPT_N,
            r=8,
            p=1,
        )
        self.key = kdf.derive(password.encode("utf-8"))
        self.salt = salt
        # verify
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=SCRYPT_N,
            r=8,
            p=1,
        )
        kdf.verify(password.encode("utf-8"), self.key)


class FileEncryptor:
    """File wrapper that encrypts the content of the file on the fly"""

    # TODO: save salt in the file
    # pylint: disable=invalid-name
    def __init__(self, path: str, key: EncryptionKey):
        self.key = key
        self.iv = os.urandom(IV_SIZE_BYTES)
        self.encryptor = Cipher(
            algorithms.AES256(self.key.key),
            modes.GCM(self.iv),
        ).encryptor()
        self.path = path
        self._fd = None  # holding fd to a file when opened
        self.finalized = False

    def read(self, size=None):
        """reads and encrypts the file content, returns encrypted data"""
        if self.finalized:
            return b""
        args = []
        if size is not None:
            args.append(size)
        if not self._fd:
            self._fd = open(self.path, "rb")
        unencrypted_data = self._fd.read(*args)

        if unencrypted_data:
            encrypted_data = self.encryptor.update(unencrypted_data)
            if size is None:
                encrypted_data += (
                    self.encryptor.finalize()
                    + self.encryptor.tag
                    + self.iv
                    + self.key.salt
                )
                self.finalized = True
        else:
            encrypted_data = (
                self.encryptor.finalize() + self.encryptor.tag + self.iv + self.key.salt
            )
            self.finalized = True
        return encrypted_data

    def close(self):
        """closes the underlying file if open"""
        if self._fd:
            self._fd.close()
            self._fd = None

    def encrypt_to_file(self, destination):
        """
        encrypts the underlying file and writes it to destination
        using incremental reads
        """
        with open(destination, "wb") as f:
            while True:
                data = self.read(BUFFER_SIZE_BYTES)
                if not data:
                    break
                f.write(data)


class FileDecryptor:
    """
    Decrypts a file encrypted with FileEncryptor
    Needs to detect all crypto material before the
    decryption key is reconstructed from password.
    """

    # pylint: disable=invalid-name
    def __init__(self, path: str, password: str | None = None):
        self.path = path
        self._fd = None
        self.finalized = False
        self.decryptor = None
        self.max_read_pos = (
            os.path.getsize(path) - IV_SIZE_BYTES - TAG_SIZE_BYTES - SALT_SIZE_BYTES
        )
        if self.max_read_pos < 0:
            raise IOError(
                f"File size {os.path.getsize(path)} of {path} is too small to be decrypted."
                "Could not get all crypto metadata."
            )
        self._init_crypto(password=password)

    def _init_crypto(self, password: str | None = None):
        """Inits crypto material based on the content of the file and caches the key"""
        # TODO: ask for password interactively if not provided
        if password is None:
            raise NotImplementedError("Password must be provided")
        self._fd = open(self.path, "rb")
        self._fd.seek(-SALT_SIZE_BYTES - IV_SIZE_BYTES - TAG_SIZE_BYTES, os.SEEK_END)
        self.tag = self._fd.read(TAG_SIZE_BYTES)
        self.iv = self._fd.read(IV_SIZE_BYTES)
        salt = self._fd.read(SALT_SIZE_BYTES)
        self._fd.seek(0)
        if _KEYSTORE.get(salt):
            self.key = _KEYSTORE[salt]
        else:
            self.key = EncryptionKey(password=password, salt=salt)
            _KEYSTORE[salt] = self.key

        self.decryptor = Cipher(
            algorithms.AES256(self.key.key),
            modes.GCM(self.iv, self.tag),
        ).decryptor()

    def read(self, size=None):
        """
        reads an encrypted underlying file and
        decrypts the file content, returns decrypted data
        """
        if self.finalized:
            return b""
        args = []
        if size is None:
            args.append(self.max_read_pos)  # read the whole file except the iv+tag
        else:
            args.append(min(size, self.max_read_pos - self._fd.tell()))
        encrypted_data = self._fd.read(*args)
        decrypted_data = self.decryptor.update(encrypted_data)
        if not encrypted_data:
            self.finalized = True
            return self.decryptor.finalize()
        # if we read it all in one go, we need to finalize as there won't be
        # any other read call coming
        if self._fd.tell() == self.max_read_pos:
            self.finalized = True
            decrypted_data += self.decryptor.finalize()
        return decrypted_data

    def close(self):
        """closes the underlying file if open"""
        if self._fd:
            self._fd.close()
            self._fd = None


def _encrypt(key: EncryptionKey, plaintext: bytes):
    """Encrypts plaintext byte data with the given key and returns a tuple of iv, ciphertext, tag"""
    # pylint: disable=invalid-name
    # Generate a random 96-bit IV.
    iv = os.urandom(IV_SIZE_BYTES)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES256(key.key),
        modes.GCM(iv),
    ).encryptor()

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # tag is 128bits (16 bytes)
    return (iv, ciphertext, encryptor.tag)


def _decrypt(key: EncryptionKey, iv: bytes, ciphertext: bytes, tag: bytes):
    """Decrypts ciphertext byte data with the given key and returns the plaintext"""
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    # pylint: disable=invalid-name
    decryptor = Cipher(
        algorithms.AES256(key.key),
        modes.GCM(iv, tag),
    ).decryptor()

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_filename(key: EncryptionKey, plaintext: str) -> bytes:
    """Encrypts a filename with the given key and returns a base64 encoded string"""
    # pylint: disable=invalid-name
    iv, ciphertext, tag = _encrypt(key, plaintext.encode("utf-8"))
    result = base64.urlsafe_b64encode(iv + tag + key.salt + ciphertext)
    return result


def decrypt_filename(encrypted_filename: bytes, password=None) -> str:
    """Decrypts a filename with the given key and returns a base64 encoded string"""
    # pylint: disable=invalid-name
    if password is None:
        raise NotImplementedError("Password must be provided")
    decoded = base64.urlsafe_b64decode(encrypted_filename)
    if len(decoded) < IV_SIZE_BYTES + TAG_SIZE_BYTES + SALT_SIZE_BYTES:
        raise ValueError("Invalid encrypted filename. Too short to get all required metadata.")
    iv = decoded[:IV_SIZE_BYTES]
    tag = decoded[IV_SIZE_BYTES : IV_SIZE_BYTES + TAG_SIZE_BYTES]
    salt = decoded[
        IV_SIZE_BYTES
        + TAG_SIZE_BYTES : IV_SIZE_BYTES
        + TAG_SIZE_BYTES
        + SALT_SIZE_BYTES
    ]
    try:
        key = _KEYSTORE[salt]
    except KeyError:
        log.debug(f"Generating decryption key for salt {salt}")
        # TODO: ask for password interactively if not provided
        key = EncryptionKey(password=password, salt=salt)
        _KEYSTORE[salt] = key
    ciphertext = decoded[IV_SIZE_BYTES + TAG_SIZE_BYTES + SALT_SIZE_BYTES :]
    return _decrypt(key, iv, ciphertext, tag).decode("utf-8")


def encrypt_directory(key: EncryptionKey, directory, destination):
    """encrypts all files and directories in directory and writes them to destination"""
    # todo: make sure destination is empty

    for root, dirs, files in os.walk(directory):
        for fname in files:
            encrypted_filename = encrypt_filename(key, fname).decode("utf-8")
            log.debug(f"Encrypting file {fname} -> {encrypted_filename}")
            file_encryptor = FileEncryptor(os.path.join(root, fname), key)
            file_encryptor.encrypt_to_file(
                os.path.join(destination, encrypted_filename)
            )

        # for d in dirs:
        #     encrypted_dir = encrypt_filename(key, d).decode("utf-8")
        #     log.debug(f"Encrypting directory {d} -> {encrypted_dir}")
        #     os.mkdir(os.path.join(destination, encrypted_dir))
