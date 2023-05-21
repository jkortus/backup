import os

import base64

# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SCRYPT_N = 2**14
BUFFER_SIZE_BYTES = 32 * 1024 * 1024
IV_SIZE_BYTES = 12
TAG_SIZE_BYTES = 16


class FileEncryptor:
    def __init__(self, path, key):
        self.key = key
        self.iv = os.urandom(IV_SIZE_BYTES)
        self.encryptor = Cipher(
            algorithms.AES256(key),
            modes.GCM(self.iv),
        ).encryptor()
        self.path = path
        self._fd = None  # holding fd to a file when opened
        self.finalized = False

    def read(self, size=None):
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
                    self.encryptor.finalize() + self.encryptor.tag + self.iv
                )
                self.finalized = True
        else:
            encrypted_data = self.encryptor.finalize() + self.encryptor.tag + self.iv
            self.finalized = True
        return encrypted_data

    def close():
        if self._fd:
            self._fd.close()
            self._fd = None


class FileDecryptor:
    def __init__(self, path, key):
        self.key = key
        self.path = path
        self._fd = None
        self.finalized = False
        self.decryptor = None
        self._init_crypto()
        self.max_read_pos = os.path.getsize(path) - IV_SIZE_BYTES - TAG_SIZE_BYTES

    def _init_crypto(self):
        self._fd = open(self.path, "rb")
        self._fd.seek(-IV_SIZE_BYTES - TAG_SIZE_BYTES, os.SEEK_END)
        self.tag = self._fd.read(TAG_SIZE_BYTES)
        self.iv = self._fd.read(IV_SIZE_BYTES)
        self._fd.seek(0)
        self.decryptor = Cipher(
            algorithms.AES256(self.key),
            modes.GCM(self.iv, self.tag),
        ).decryptor()

    def read(self, size=None):
        if self.finalized:
            return b""
        args = []
        if size is None:
            args.append(self.max_read_pos)  # read the whole file except the iv+tag
        else:
            args.append(min(size, self.max_read_pos - self._fd.tell()))
        encrypted_data = self._fd.read(*args)
        if not encrypted_data:
            self.finalized = True
            return self.decryptor.finalize()

        return self.decryptor.update(encrypted_data)


def generate_key(password):
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_N,
        r=8,
        p=1,
    )
    key = kdf.derive(password.encode("utf-8"))

    # verify
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_N,
        r=8,
        p=1,
    )
    kdf.verify(password.encode("utf-8"), key)

    return key


def get_encryptor(key):
    """Returns a tuple of (iv, AES256 encryptor)"""
    # Generate a random 96-bit IV.
    iv = os.urandom(IV_SIZE_BYTES)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES256(key),
        modes.GCM(iv),
    ).encryptor()

    return (iv, encryptor)


def get_decryptor(key, iv, tag):
    """
    Returns an AES256 decryptor
    key: 256bit key (32 bytes)
    iv: 96bit iv (12 bytes)
    tag: 128bit tag (16 bytes)
    """
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES256(key),
        modes.GCM(iv, tag),
    ).decryptor()

    return decryptor


def _encrypt(key, plaintext):
    # Generate a random 96-bit IV.
    iv = os.urandom(IV_SIZE_BYTES)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES256(key),
        modes.GCM(iv),
    ).encryptor()

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # tag is 128bits (16 bytes)
    return (iv, ciphertext, encryptor.tag)


def _decrypt(key, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES256(key),
        modes.GCM(iv, tag),
    ).decryptor()

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()


#
print("Generating key")
key = generate_key("password")
iv, encryptor = get_encryptor(key)
input_file = "./data"
encrypted_file = "./data.enc"


def encrypt_file(input_file, encrypted_file):
    with open(input_file, "rb") as f:
        with open(encrypted_file, "wb") as ef:
            data = f.read(BUFFER_SIZE_BYTES)
            while data:
                ef.write(encryptor.update(data))
                data = f.read(BUFFER_SIZE_BYTES)
            ef.write(encryptor.finalize())
            ef.write(encryptor.tag)
            print(f"tag size: {len(encryptor.tag)}")
            ef.write(iv)


def encrypt_filename(key, plaintext):
    iv, ciphertext, tag = _encrypt(key, plaintext.encode("utf-8"))
    return base64.b64encode(iv + tag + ciphertext)


def decrypt_filename(key, encrypted_filename):
    decoded = base64.b64decode(encrypted_filename)
    iv = decoded[:IV_SIZE_BYTES]
    tag = decoded[IV_SIZE_BYTES : IV_SIZE_BYTES + TAG_SIZE_BYTES]
    ciphertext = decoded[IV_SIZE_BYTES + TAG_SIZE_BYTES :]
    return _decrypt(key, iv, ciphertext, tag).decode("utf-8")


def decrypt_file(encrypted_file, destination):
    file_size = os.path.getsize(encrypted_file)
    last_read_byte_pos = file_size - TAG_SIZE_BYTES - IV_SIZE_BYTES
    if last_read_byte_pos < 0:
        raise IOError(
            f"File size {file_size} of {encrypted_file} is too small to be decrypted (does not contain TAG and IV at least)."
        )
    with open(encrypted_file, "rb") as ef:
        # seek to tag+iv entry
        ef.seek(file_size - TAG_SIZE_BYTES - IV_SIZE_BYTES)
        tag = ef.read(TAG_SIZE_BYTES)
        iv = ef.read(IV_SIZE_BYTES)
        ef.seek(0)
        decryptor = get_decryptor(key, iv, tag)

        with open(destination, "wb") as f:
            while True:
                if ef.tell() + BUFFER_SIZE_BYTES <= last_read_byte_pos:
                    data = ef.read(BUFFER_SIZE_BYTES)
                    f.write(decryptor.update(data))
                else:
                    data = ef.read(last_read_byte_pos - ef.tell())
                    f.write(decryptor.update(data))
                    f.write(decryptor.finalize())
                    break


encrypted_filename = encrypt_filename(key, input_file * 8)
print("Encrypted filename: %s" % encrypted_filename)
print("Decrypted filename: %s" % decrypt_filename(key, encrypted_filename))
print("Encrypting file")
file_encryptor = FileEncryptor(input_file, key)
with open(encrypted_file, "wb") as ef:
    data = file_encryptor.read()
    ef.write(data)

print("Decrypting file")
file_decryptor = FileDecryptor(encrypted_file, key)
with open("./data.dec", "wb") as f:
    data = file_decryptor.read()
    f.write(data)

# encrypt_file(input_file, encrypted_file)
# print("Decrypting file")
# decrypt_file(encrypted_file, "./data.dec")


# iv, ciphertext, tag = encrypt(
#     key, b"a secret message!"
# )
# print(f"iv: {iv}, ciphertext: {ciphertext}, tag: {tag}")

# print(decrypt(key, iv, ciphertext, tag))
