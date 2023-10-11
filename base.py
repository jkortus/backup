""" Encrypt files and directories for backup on untrusted storage"""
import base64
import copy
import getpass
import logging
import os
from io import BytesIO, IOBase
import pathlib
from copy import deepcopy
from typing import Dict, Union, Any


# pylint: disable=logging-fstring-interpolation
# pylint: disable=too-many-lines
import cryptography.exceptions

# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
    AEADDecryptionContext,
)

# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


import filesystems
from filesystems import MAX_FILENAME_LENGTH, MAX_PATH_LENGTH, Filesystem

logging.basicConfig(level=logging.CRITICAL)
log = logging.getLogger(__name__)
log.setLevel(logging.CRITICAL)
filesystems.log.setLevel(logging.CRITICAL)

SCRYPT_N = 2**20
BUFFER_SIZE_BYTES = 4 * 1024 * 1024
IV_SIZE_BYTES = 12
TAG_SIZE_BYTES = 16
SALT_SIZE_BYTES = 16

# https://en.wikipedia.org/wiki/Galois/Counter_Mode
MAX_FILE_SIZE = int((2**39 - 256) / 8)

# base64 encoded output is always multiple of 4 bytes
# its 6 to 8 bits encoding
# int(a/b) * b = floor(a/b) :)
MAGIC_FILENAME_HEADER = b"\x00"  # something that is very unlikely in filename
MAX_UNENCRYPTED_FILENAME_LENGTH = (
    int(int(MAX_FILENAME_LENGTH / 4) * 4 / 8 * 6)
    - IV_SIZE_BYTES
    - TAG_SIZE_BYTES
    - SALT_SIZE_BYTES
    - len(MAGIC_FILENAME_HEADER)
)
_KEYSTORE: Dict[bytes, "EncryptionKey"] = {}  # cached keys for detected salts
_ENCRYPTION_KEY: Union["EncryptionKey", None] = None  # cached encryption key
_PASSWORD: str | None = None  # cached password
STATUS_REPORTER: Union[
    "StatusReporter", None
] = None  # StatusReporter instance for progress monitoring, optional

log.debug(f"Max unencrypted filename length: {MAX_UNENCRYPTED_FILENAME_LENGTH}")
log.debug(f"Max size of unecrypted input: {MAX_FILE_SIZE} bytes")


class DecryptionError(Exception):
    """Raised when decryption fails"""


class FSFile:  # pylint: disable=too-few-public-methods
    """File system file"""

    def __init__(self, name: str, filesystem: Filesystem):
        self.name = name
        self.filesystem = filesystem
        self.is_encrypted = is_encrypted(self.name)
        if self.is_encrypted:
            self.decrypted_name = decrypt_filename(self.name.encode("utf-8"))
        else:
            self.decrypted_name = self.name


class FSDirectory:
    """File system directory"""

    def __init__(self, path: str, filesystem: Filesystem):
        """
        path: path to the directory. If it contains only a name without a full path
              (no parent dir), current working directory will be the parent.
        filesystem: filesystem object to use for operations
        """
        self.name = os.path.basename(path)
        self.parent = os.path.dirname(path)
        self.filesystem = filesystem
        if self.parent == "":
            self.parent = self.filesystem.getcwd()
        self.files: list["FSFile"] = []
        self.directories: list["FSDirectory"] = []
        self.is_encrypted = is_encrypted(self.name)
        if self.is_encrypted:
            self.decrypted_name = decrypt_filename(self.name.encode("utf-8"))
        else:
            self.decrypted_name = self.name

    @property
    def abs_path(self) -> str:
        """returns absolute path to the directory within its filesystem"""
        return os.path.join(self.parent, self.name)

    @property
    def abs_decrypted_path(self) -> str:
        """returns absolute decrypted path to the directory"""
        path_parts = pathlib.Path(self.abs_path).parts
        dec_parts = []
        assert len(path_parts) > 0  # to justify pylint-disable at the end
        for part in path_parts:
            if is_encrypted(part):
                dec_parts.append(decrypt_filename(part.encode("utf-8")))
            else:
                dec_parts.append(part)
        # pylint: disable=no-value-for-parameter
        return os.path.join(*dec_parts)

    def add_directory(self, directory: "FSDirectory") -> None:
        """adds a directory (FSDirectory) to the directory tree"""
        if not isinstance(directory, self.__class__):
            raise TypeError(
                f"Invalid arg for directory, expected {self.__class__}, got {type(directory)}"
            )
        if directory.filesystem != self.filesystem:
            raise ValueError(
                f"Invalid filesystem for directory {directory.name}, "
                f"expected {self.filesystem} got {directory.filesystem}."
            )
        if directory.name in self.dir_names() | self.file_names():
            raise ValueError(
                f"Directory {directory.name} already exists in {self.name}"
            )
        if directory.parent != os.path.join(self.parent, self.name):
            # warning here, as we expect the caller to be nesting
            # proper directories with proper internals.
            log.warning(
                f"Unexpected parent for directory "
                f"{os.path.join(directory.parent,directory.name)}, "
                f"expected {self.parent}, got {directory.parent}. "
                f"If it is nested subtree, all subdirs will have wrong parent."
            )
        directory.parent = os.path.join(self.parent, self.name)
        self.directories.append(directory)

    def add_file(self, file: FSFile) -> None:
        """adds a file (FSFile) to the directory tree"""
        if not isinstance(file, FSFile):
            raise TypeError(
                f"Invalid arg for file, expected {FSFile}, got {type(file)}"
            )
        if file.name in self.file_names() | self.dir_names():
            raise ValueError(f"File {file.name} already exists in {self.name}")
        if file.filesystem != self.filesystem:
            raise ValueError(
                f"Invalid filesystem for file {file.name}, "
                f"expected {self.filesystem} got {file.filesystem}."
            )
        self.files.append(file)

    def get_directory(self, name: str) -> "FSDirectory":
        """
        returns a directory object (FSDirectory) by name
        raises KeyError if not found
        If the directory is encrypted, the decrypted name is used.
        """
        for directory in self.directories:
            if directory.is_encrypted:
                if directory.decrypted_name == name:
                    return directory
            elif directory.name == name:
                return directory
        raise KeyError(f"Directory {name} not found")

    def is_empty(self) -> bool:
        """returns True if the directory is empty (has no subdirs and no files)"""
        return len(self.files) == 0 and len(self.directories) == 0

    def dir_names(self) -> set[str]:
        """returns a set of directory names"""
        result = set()
        # pylint: disable=invalid-name
        for d in self.directories:
            if d.is_encrypted:
                result.add(d.decrypted_name)
            else:
                result.add(d.name)
        return result

    def file_names(self) -> set[str]:
        """returns a set of file names"""
        result = set()
        # pylint: disable=invalid-name
        for f in self.files:
            if f.is_encrypted:
                result.add(f.decrypted_name)
            else:
                result.add(f.name)
        return result

    def get_file(self, name: str) -> FSFile:
        """returns a file object (FSFile) by (decripted) name"""
        for file in self.files:
            if file.is_encrypted:
                if file.decrypted_name == name:
                    return file
            elif file.name == name:
                return file
        raise KeyError(f"File {name} not found")

    def get_files(self) -> list[FSFile]:
        """returns a list of FSFile objects for all directly nested files"""
        return copy.deepcopy(self.files)

    def __str__(self) -> str:
        return f"FSDirectory(name={self.name}, parent={self.parent}, encrypted={self.is_encrypted})"

    def pretty_print(self, indent: int = 2) -> None:
        """prints the directory structure"""
        print(self.dump(indent=indent))

    def dump(
        self,
        indent: int = 2,
        show_encrypted_fnames: bool = False,
        show_filesystem: bool = False,
    ) -> str:
        """returns a string representation of the directory structure"""
        result = ""
        encryption_info = ""
        if self.is_encrypted:
            display_name = f"{self.decrypted_name}"
            if show_encrypted_fnames:
                encryption_info = f"(encrypted as: {self.name})"
            else:
                encryption_info = "(encrypted)"
        else:
            display_name = f"{self.name}"
            encryption_info = " (NOT encrypted)"
        if show_filesystem:
            display_name += f" (fs: {self.filesystem})"
        result += f"{' ' * indent}[{display_name}] {encryption_info}\n"
        for directory in self.directories:
            result += directory.dump(
                indent=indent + 2,
                show_encrypted_fnames=show_encrypted_fnames,
                show_filesystem=show_filesystem,
            )
        encryption_info = ""
        for file in self.files:
            if file.is_encrypted:
                display_name = f"{file.decrypted_name}"
                if show_encrypted_fnames:
                    encryption_info = f"(encrypted as: {file.name})"
                else:
                    encryption_info = "(encrypted)"
            else:
                display_name = f"{file.name}"
                encryption_info = " (NOT encrypted)"
            if show_filesystem:
                display_name += f" (fs: {file.filesystem})"
            result += f"{' ' * (indent+2)}{display_name} {encryption_info}\n"
        return result

    def to_path_list(self) -> list[tuple[str, str]]:
        """
        returns a list of tuples (decrypted_path, encrypted_path)
        for all files and directories in the tree
        """
        result = []
        for directory in self.directories:
            result.append((directory.abs_decrypted_path, directory.abs_path))
            result.extend(directory.to_path_list())
        for file in self.files:
            result.append(
                (
                    os.path.join(self.abs_decrypted_path, file.decrypted_name),
                    os.path.join(self.abs_path, file.name),
                )
            )
        return result

    @classmethod
    def from_filesystem(
        cls, path: str, filesystem: Filesystem, recursive: bool = True
    ) -> "FSDirectory":
        """creates a FSdirectory tree from the file system"""
        if not filesystem.is_dir(path):
            raise IOError(f"Directory {path} does not exist or is not a directory")
        with filesystem.cwd_cm(path):
            _, dirs, files = next(filesystem.walk("."))
            # log.debug(f"Content of {path}: dirs: {dirs} files: {files}")
        directory = cls(path=path, filesystem=filesystem)
        for dname in dirs:
            if recursive:
                new_dir = cls.from_filesystem(
                    path=os.path.join(path, dname), filesystem=filesystem
                )
                new_dir.parent = os.path.join(directory.parent, directory.name)
                directory.add_directory(new_dir)
            else:
                new_dir = FSDirectory(
                    path=os.path.join(path, dname), filesystem=filesystem
                )
                new_dir.parent = os.path.join(directory.parent, directory.name)
                directory.add_directory(new_dir)
        for fname in files:
            directory.add_file(FSFile(name=fname, filesystem=filesystem))
        return directory

    def one_way_diff(self, other: "FSDirectory") -> Union["FSDirectory", None]:
        """
        compares two directory trees
        returns a new FSDirectory with entries that are not in self
        and are in the other, including their parent elements if nested deeper.

        In other words returns new elements in the other.

        Returns None if the trees are identical
        """
        result = None

        for directory in other.directories:
            dir_name = (
                directory.name
                if not directory.is_encrypted
                else directory.decrypted_name
            )
            if dir_name not in self.dir_names():
                # if the directory is completely new, add the whole subtree from other
                subtree_copy = deepcopy(directory)
                if result is None:
                    # return copy of self without any nested elements (dirs, files)
                    result = self.__class__(path=self.name, filesystem=self.filesystem)
                result.add_directory(subtree_copy)
            else:
                # if the directory already exists, compare the subtrees
                subresult = self.get_directory(dir_name).one_way_diff(directory)
                if subresult:
                    if result is None:
                        result = self.__class__(
                            path=self.name, filesystem=self.filesystem
                        )
                    result.add_directory(subresult)

        for fname in other.file_names():
            filename = (
                fname
                if not is_encrypted(fname)
                else decrypt_filename(fname.encode("utf-8"))
            )
            if filename not in self.file_names():
                if result is None:
                    result = self.__class__(path=self.name, filesystem=self.filesystem)
                result.add_file(FSFile(name=fname, filesystem=self.filesystem))

        return result

    def __sub__(self, other: "FSDirectory") -> "FSDirectory|None":
        """returns a new FSDirectory with entries that are not in self
        and are in the other, including their parent elements if nested deeper.

        In other words returns new elements in the other.
        """
        if not isinstance(other, self.__class__):
            raise TypeError(
                f"Invalid arg for other, expected {self.__class__}, got {type(other)}"
            )
        return other.one_way_diff(self)

    def __eq__(self, other: Any) -> bool:
        """compares two directory trees"""
        if not isinstance(other, self.__class__):
            raise TypeError(
                f"Invalid arg for other, expected {self.__class__}, got {type(other)}"
            )
        return self.one_way_diff(other) is None and other.one_way_diff(self) is None

    def __deepcopy__(self, memo: dict) -> "FSDirectory":  # type: ignore[type-arg]
        """creates deep copy that will share filesystem reference with original"""
        cls = self.__class__
        result = cls.__new__(cls)
        memo[id(self)] = result
        for k, v in self.__dict__.items():  # pylint: disable=invalid-name
            if k == "filesystem":
                setattr(result, k, self.filesystem)
                continue
            setattr(result, k, deepcopy(v, memo))
        return result


class EncryptionKey:  # pylint: disable=too-few-public-methods
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

    # pylint: disable=invalid-name
    def __init__(
        self,
        path: str,
        key: EncryptionKey,
        filesystem: Filesystem,
    ):
        self.key = key
        self.iv = os.urandom(IV_SIZE_BYTES)
        self.encryptor = Cipher(
            algorithms.AES256(self.key.key),
            modes.GCM(self.iv),
        ).encryptor()
        self.path = path
        self.filesystem = filesystem
        self._fd: BytesIO | None = None  # holding fd to a file when opened
        self.finalized = False

    def read(self, size: int | None = None) -> bytes:
        """reads and encrypts the file content, returns encrypted data"""
        if self.finalized:
            return b""
        args = []
        if size is not None:
            args.append(size)
        if not self._fd:
            if len(self.path) > MAX_PATH_LENGTH:
                dirpath = os.path.dirname(self.path)
                filename = os.path.basename(self.path)
                with self.filesystem.cwd_cm(dirpath):
                    self._fd = self.filesystem.open(filename, "rb")
            else:
                self._fd = self.filesystem.open(self.path, "rb")
            file_size = self.filesystem.get_size(self.path)
            if file_size > MAX_FILE_SIZE:
                raise IOError(
                    f"File size {file_size} of {self.path} is over maximum size"
                    f" limit of {MAX_FILE_SIZE} bytes and cannot be encrypted. "
                )
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

    def close(self) -> None:
        """closes the underlying file if open"""
        if self._fd:
            self._fd.close()
            self._fd = None

    def encrypt_to_file(
        self, destination: str, filesystem: Filesystem, overwrite: bool = False
    ) -> None:
        """
        encrypts the underlying file and writes it to destination
        using incremental reads
        """
        if filesystem.exists(destination) and not overwrite:
            raise IOError(
                f"Destination file {destination} exists and overwrite is disabled."
            )
        with filesystem.open(destination, "wb") as f:
            try:
                while True:
                    data = self.read(BUFFER_SIZE_BYTES)
                    if not data:
                        break
                    f.write(data)
            except IOError as e:
                log.error(f"Error encountered: {e}")
                filesystem.unlink(
                    destination
                )  # no not keep partial files present on the disk
                raise


class FileDecryptor:
    # pylint: disable=too-many-instance-attributes
    """
    Decrypts a file encrypted with FileEncryptor
    Needs to detect all crypto material before the
    decryption key is reconstructed from password.
    """

    # pylint: disable=invalid-name
    def __init__(self, path: str, filesystem: Filesystem):
        self.path = path
        self._fd: IOBase | None = None
        self.finalized = False
        self.decryptor: AEADDecryptionContext | None = None
        self.filesystem = filesystem
        size = self.filesystem.get_size(path)
        self.max_read_pos = size - IV_SIZE_BYTES - TAG_SIZE_BYTES - SALT_SIZE_BYTES
        if self.max_read_pos < 0:
            raise IOError(
                f"File size {size} of {path} is too small to be decrypted."
                "Could not get all crypto metadata."
            )
        self._init_crypto()

    def _init_crypto(self) -> None:
        """Inits crypto material based on the content of the file and caches the key"""
        self._fd = self.filesystem.open(self.path, "rb")
        self._fd.seek(-SALT_SIZE_BYTES - IV_SIZE_BYTES - TAG_SIZE_BYTES, os.SEEK_END)
        self.tag = self._fd.read(TAG_SIZE_BYTES)
        self.iv = self._fd.read(IV_SIZE_BYTES)
        salt = self._fd.read(SALT_SIZE_BYTES)
        self._fd.seek(0)
        self.key = get_key(salt=salt)

        self.decryptor = Cipher(
            algorithms.AES256(self.key.key),
            modes.GCM(self.iv, self.tag),
        ).decryptor()
        self.crypto_init_done = True

    def read(self, size: int | None = None) -> bytes:
        """
        reads an encrypted underlying file and
        decrypts the file content, returns decrypted data
        """
        if not self.crypto_init_done:
            self._init_crypto()
        if self.finalized:
            return b""
        assert self._fd is not None
        assert self.decryptor is not None
        args = []
        if size is None:
            args.append(self.max_read_pos)  # read the whole file except the iv+tag
        else:
            args.append(min(size, self.max_read_pos - self._fd.tell()))
        encrypted_data = self._fd.read(*args)
        decrypted_data = self.decryptor.update(encrypted_data)
        try:
            if not encrypted_data:
                self.finalized = True
                return self.decryptor.finalize()
            # if we read it all in one go, we need to finalize as there won't be
            # any other read call coming
            if self._fd.tell() == self.max_read_pos:
                self.finalized = True
                decrypted_data += self.decryptor.finalize()
        except cryptography.exceptions.InvalidTag as ex:
            log.debug(f"Failed to decrypt file {self.path}: {ex}", exc_info=True)
            raise DecryptionError(
                f"Failed to decrypt file {self.path}, invalid password given or file is corrupted."
            ) from ex
        return decrypted_data

    def decrypt_to_file(
        self,
        destination: str,
        filesystem: Filesystem,
        overwrite: bool = False,
        keep_corrupted: bool = False,
    ) -> None:
        """
        decrypts the underlying file and writes it to destination
        using incremental reads
        """
        if filesystem.exists(destination) and not overwrite:
            raise IOError(
                f"Destination file {destination} exists and overwrite is disabled."
            )
        if not self.crypto_init_done:
            self._init_crypto()

        try:
            with filesystem.open(destination, "wb") as f:
                while True:
                    data = self.read(BUFFER_SIZE_BYTES)
                    if not data:
                        break
                    f.write(data)
        except DecryptionError as ex:
            log.error(f"Error encountered: {ex}")
            if not keep_corrupted:
                log.error(f"Removing corrupted file {destination}")
                filesystem.unlink(destination)
            raise

    def close(self) -> None:
        """closes the underlying file if open"""
        if self._fd:
            self._fd.close()
            self._fd = None


class StatusReporter:
    # pylint: disable=too-few-public-methods
    """
    Collects and reports events to inform the user
    about a long running process.
    """

    def __init__(self, terminal_width: int = 80):
        self.files_processed = 0
        self.files_skipped = 0
        self.terminal_width = terminal_width

    def event(self, name: str, *args: Any) -> None:
        """reports an event"""
        if name == "encrypt_file":
            # if self.files_processed == 0:
            #    print("\n")
            self.files_processed += 1
            # seek at start of the line
            intro = "Encrypting file "
            replacement = "[...]"
            display_name = args[0]
            if len(intro + display_name) > self.terminal_width:
                display_name = (
                    replacement
                    + display_name[
                        -(self.terminal_width - len(intro) - len(replacement)) :
                    ]
                )
            info_line = f"{intro}{display_name}"
            print(f"{info_line}", end="\n", flush=True)

        elif name == "decrypt_file":
            # if self.files_processed == 0:
            #    print("\n")
            self.files_processed += 1
            # seek at start of the line
            intro = "Decrypting file "
            replacement = "[...]"
            display_name = args[0]
            if len(intro + display_name) > self.terminal_width:
                display_name = (
                    replacement
                    + display_name[
                        -(self.terminal_width - len(intro) - len(replacement)) :
                    ]
                )
            info_line = f"{intro}{display_name}"
            print(f"{info_line}", end="\n", flush=True)

        elif name == "skip_file":
            self.files_skipped += 1
            intro = "Skipping file/dir (already encrypted in target): "
            replacement = "[...]"
            display_name = args[0]
            if len(intro + display_name) > self.terminal_width:
                display_name = (
                    replacement
                    + display_name[
                        -(self.terminal_width - len(intro) - len(replacement)) :
                    ]
                )
            info_line = f"{intro}{display_name}"
            print(f"{info_line}", end="\n", flush=True)
        else:
            log.debug(f"Unknown event ignored: {name} {args}")


def _encrypt(key: EncryptionKey, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
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


def _decrypt(key: EncryptionKey, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
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
    if len(plaintext) > MAX_UNENCRYPTED_FILENAME_LENGTH:
        raise ValueError(
            f"Filename {plaintext} is too long ({len(plaintext)}). "
            f"Max length is {MAX_UNENCRYPTED_FILENAME_LENGTH}."
        )
    iv, ciphertext, tag = _encrypt(key, plaintext.encode("utf-8"))
    result = base64.urlsafe_b64encode(
        MAGIC_FILENAME_HEADER + iv + tag + key.salt + ciphertext
    )
    if len(result) > MAX_FILENAME_LENGTH:
        raise RuntimeError(
            f"Encrypted filename {result!r} is too long ({len(result)}). "
            f"Max length is {MAX_FILENAME_LENGTH}. This is a bug. "
            f"MAX_UNENCRYPTED_FILENAME_LENGTH={MAX_UNENCRYPTED_FILENAME_LENGTH} "
            "needs to be lowered."
        )
    # translation on the result to avoid "=" in the filename
    # due to aws object name restrictions
    result = result.replace(b"=", b".")
    return result


def decrypt_filename(encrypted_filename: bytes) -> str:
    """Decrypts a filename with the given key and returns a base64 encoded string"""
    # pylint: disable=invalid-name
    if not isinstance(encrypted_filename, bytes):
        raise TypeError(
            f"Invalid arg for encrypted_filename, expected bytes, "
            f"got {type(encrypted_filename)}"
        )
    try:
        # translation of chars back, see encrypt_filename for more info
        encrypted_filename = encrypted_filename.replace(b".", b"=")
        decoded = base64.urlsafe_b64decode(encrypted_filename)
    except Exception as ex:
        # log.error(f"Failed to decode filename {encrypted_filename}: {ex}")
        raise ValueError(
            f"Failed to decode filename {encrypted_filename!r}. "
            f"Probably invalid (non-encrypted) filename for decryption?: {ex}"
        ) from ex

    if len(decoded) < IV_SIZE_BYTES + TAG_SIZE_BYTES + SALT_SIZE_BYTES + len(
        MAGIC_FILENAME_HEADER
    ):
        raise ValueError(
            f"Invalid encrypted filename ({encrypted_filename!r}). "
            "Too short to get all required metadata."
        )
    magic_header = decoded[  # pylint: disable=unused-variable
        : len(MAGIC_FILENAME_HEADER)
    ]
    header_len = len(MAGIC_FILENAME_HEADER)
    iv = decoded[header_len : IV_SIZE_BYTES + header_len]
    tag = decoded[
        IV_SIZE_BYTES + header_len : IV_SIZE_BYTES + TAG_SIZE_BYTES + header_len
    ]
    salt = decoded[
        IV_SIZE_BYTES
        + TAG_SIZE_BYTES
        + header_len : IV_SIZE_BYTES
        + TAG_SIZE_BYTES
        + SALT_SIZE_BYTES
        + header_len
    ]
    key = get_key(salt=salt)
    ciphertext = decoded[
        IV_SIZE_BYTES + TAG_SIZE_BYTES + SALT_SIZE_BYTES + header_len :
    ]
    try:
        result = _decrypt(key, iv, ciphertext, tag).decode("utf-8")
        if not result == os.path.basename(result):
            raise ValueError(
                f"Invalid decrypted filename ({result}). "
                "Potentially unsafe filename!"
            )
        return result
    except cryptography.exceptions.InvalidTag as ex:
        log.debug(
            f"Failed to decrypt filename {encrypted_filename!r}: {ex}", exc_info=True
        )
        raise DecryptionError(
            f"Failed to decrypt filename {encrypted_filename!r}, invalid password given?"
        ) from ex
    except:
        log.error("Unexpected error durin filename decryption:", exc_info=True)
        raise


def encrypt_directory(source: FSDirectory, destination: FSDirectory) -> None:
    """encrypts all files and directories in directory and writes them to destination"""
    log.debug(f"encrypt_directory({source} -> {destination})")
    if not (isinstance(source, FSDirectory) and isinstance(destination, FSDirectory)):
        raise TypeError(
            f"Invalid arg for source or destination, expected FSDirectory, "
            f"got {type(source)} and {type(destination)}"
        )
    destination.filesystem.makedirs(destination.abs_path, exist_ok=True)
    # use one key for all files in a run. Different runs (for new files for instance)
    # will use different keys
    key = get_key()
    if not source.filesystem.is_dir(source.abs_path):
        raise ValueError(
            f"Directory {source.name} does not exist or is not a directory"
        )

    for fname in source.file_names():
        source_abs_fname = os.path.join(source.abs_path, fname)
        target_abs_fname = os.path.join(destination.abs_path, fname)
        if fname in destination.file_names():
            log.info(
                f"Skipping already encrypted file {source_abs_fname} "
                f"-> {target_abs_fname}"
            )
            report_event("skip_file", source_abs_fname, target_abs_fname)
            continue

        encrypted_filename = encrypt_filename(key, fname).decode("utf-8")
        abs_enc_fname = os.path.join(destination.abs_path, encrypted_filename)
        log.info(f"Encrypting file {source_abs_fname} -> {abs_enc_fname}")
        file_encryptor = FileEncryptor(
            source_abs_fname, key, filesystem=source.filesystem
        )
        report_event("encrypt_file", source_abs_fname, abs_enc_fname)
        file_encryptor.encrypt_to_file(abs_enc_fname, filesystem=destination.filesystem)
        file_encryptor.close()

    for directory in source.dir_names():
        source_abs_dir_name = os.path.join(source.abs_path, directory)
        target_abs_dir_name = os.path.join(destination.abs_path, directory)
        if directory in destination.dir_names():
            log.info(
                f"Skipping already encrypted directory "
                f"{source_abs_dir_name} -> {target_abs_dir_name}"
            )
            report_event("skip_directory", source_abs_dir_name, target_abs_dir_name)
            next_target = destination.get_directory(directory)
        else:
            encrypted_dirname = encrypt_filename(key, directory).decode("utf-8")
            abs_enc_dirname = os.path.join(destination.abs_path, encrypted_dirname)
            log.info(f"Encrypting directory {source_abs_dir_name} -> {abs_enc_dirname}")
            report_event("encrypt_directory", source_abs_dir_name, abs_enc_dirname)
            destination.filesystem.mkdir(abs_enc_dirname)
            next_target = FSDirectory.from_filesystem(
                abs_enc_dirname, filesystem=destination.filesystem
            )
        encrypt_directory(source.get_directory(directory), next_target)


def decrypt_directory(source: FSDirectory, destination: FSDirectory) -> None:
    """decrypts all files and directories in directory and writes them to destination"""
    log.debug(f"decrypt_directory({source} -> {destination})")
    destination.filesystem.makedirs(destination.abs_path, exist_ok=True)
    if not source.filesystem.is_dir(source.abs_path):
        raise ValueError(
            f"Directory {source.abs_path} does not exist or is not a directory"
        )

    for file in source.get_files():
        source_abs_fname = os.path.join(source.abs_path, file.name)
        if not file.is_encrypted:
            log.error(f"File {source_abs_fname} is not encrypted! Skipping. ")
            report_event("skip_file", source_abs_fname, "<unsepcified due to error>")
            continue
        target_abs_fname = os.path.join(destination.abs_path, file.decrypted_name)
        if file.decrypted_name in destination.file_names():
            log.info(
                f"Skipping already decrypted file {source_abs_fname} ({file.decrypted_name}) "
                f"-> {target_abs_fname}"
            )
            report_event("skip_file", source_abs_fname, target_abs_fname)
            continue
        log.info(f"Decrypting file {source_abs_fname} -> {target_abs_fname}")
        report_event("decrypt_file", source_abs_fname, target_abs_fname)
        file_decryptor = FileDecryptor(source_abs_fname, filesystem=source.filesystem)
        file_decryptor.decrypt_to_file(
            target_abs_fname, filesystem=destination.filesystem
        )
        file_decryptor.close()

    for directory in source.dir_names():
        source_dir = source.get_directory(directory)
        source_abs_dir_name = os.path.join(source.abs_path, source_dir.name)
        target_abs_dir_name = os.path.join(destination.abs_path, directory)
        if directory in destination.dir_names():
            log.info(
                f"Skipping already decrypted directory "
                f"{source_abs_dir_name} -> {target_abs_dir_name}"
            )
            report_event("skip_directory", source_abs_dir_name, target_abs_dir_name)
            next_target = destination.get_directory(directory)
        else:
            log.info(
                f"Decrypting directory {source_abs_dir_name} -> {target_abs_dir_name}"
            )
            report_event("decrypt_directory", source_abs_dir_name, target_abs_dir_name)
            destination.filesystem.mkdir(target_abs_dir_name)
            next_target = FSDirectory.from_filesystem(
                target_abs_dir_name, filesystem=destination.filesystem
            )
        decrypt_directory(source.get_directory(directory), next_target)


def encrypt_file(
    source_file: str,
    source_filesystem: Filesystem,
    target_directory: str,
    target_filesystem: Filesystem,
    overwrite: bool = False,
) -> str:
    """
    Encrypts single file to a target directory
    Note: it does not decrypt the content of the directory so it cannot tell if the
    file is already encrypted there or not! If you call this function twice with the
    same arguments, it will create a new encrypted file that will decrypt to the same
    name.
    Returns encrypted name of the file
    """
    log.debug(f"encrypt_file({source_file} -> {target_directory})")
    if not source_filesystem.exists(source_file) or source_filesystem.is_dir(
        source_file
    ):
        raise ValueError(f"File {source_file} does not exist or is not a file")
    if not target_filesystem.exists(target_directory) or not target_filesystem.is_dir(
        target_directory
    ):
        raise ValueError(
            f"Directory {target_directory} does not exist or is not a directory"
        )
    target_filename = encrypt_filename(get_key(), os.path.basename(source_file)).decode(
        "utf-8"
    )
    encryptor = FileEncryptor(
        path=source_file, key=get_key(), filesystem=source_filesystem
    )
    encryptor.encrypt_to_file(
        os.path.join(target_directory, target_filename),
        filesystem=target_filesystem,
        overwrite=overwrite,
    )
    encryptor.close()
    report_event("encrypt_file", source_file, target_filename)
    return target_filename


def decrypt_file(  # pylint: disable=too-many-arguments
    source_file: str,
    source_filesystem: Filesystem,
    target_directory: str,
    target_filesystem: Filesystem,
    overwrite: bool = False,
    keep_corrupted: bool = False,
) -> None:
    """Decrypts single file to a target directory"""
    log.debug(f"decrypt_file({source_file} -> {target_directory})")
    if not source_filesystem.exists(source_file) or source_filesystem.is_dir(
        source_file
    ):
        raise ValueError(f"File {source_file} does not exist or is not a file")
    if not target_filesystem.exists(target_directory) or not target_filesystem.is_dir(
        target_directory
    ):
        raise ValueError(
            f"Directory {target_directory} does not exist or is not a directory"
        )
    decrypted_fname = decrypt_filename(os.path.basename(source_file).encode("utf-8"))
    decryptor = FileDecryptor(path=source_file, filesystem=source_filesystem)
    decryptor.decrypt_to_file(
        os.path.join(target_directory, decrypted_fname),
        filesystem=target_filesystem,
        overwrite=overwrite,
        keep_corrupted=keep_corrupted,
    )
    decryptor.close()
    report_event("decrypt_file", source_file, decrypted_fname)


def get_password(confirm: bool = True) -> str:
    """asks for password interactively"""
    global _PASSWORD  # pylint: disable=global-statement
    if _PASSWORD is not None:
        return _PASSWORD
    password = getpass.getpass(prompt="Password: ")
    if confirm:
        password_confirm = getpass.getpass(prompt="Confirm password: ")
        if password != password_confirm:
            raise ValueError("Passwords do not match!")
    _PASSWORD = password
    return password


def init_password(password: str | None, confirm: bool = True) -> None:
    """
    helper function for command line utilities
    If password is given it is used, otherwise it's asked for interactively
    """
    global _PASSWORD  # pylint: disable=global-statement
    if password is None:
        password = get_password(confirm=confirm)
    _PASSWORD = password


def get_key(salt: bytes | None = None) -> EncryptionKey:
    """
    returns EncryptionKey object
    Creates new EncryptionKey if one is not yet cached, prompting for password.
    If salt is provided, it will be used to generate a new key or to fetch
    an existing cached key from internal keystore.
    """
    global _ENCRYPTION_KEY  # pylint: disable=global-statement
    if salt is not None:
        if _KEYSTORE.get(salt):
            return _KEYSTORE[salt]
        log.info(f"Generating decryption key for salt {salt!r}")
        key = EncryptionKey(password=get_password(), salt=salt)
        _KEYSTORE[salt] = key
        # also set is as a new encryption key, since we usually will
        # use this to add more encrypted files and we do not support
        # multiple encryption keys (yet). This allows skipping unnecessary
        # extra call to generate the same key for encryption.
        _ENCRYPTION_KEY = key
        return key
    if _ENCRYPTION_KEY is None:
        log.info("Generating new encryption key...")
        _ENCRYPTION_KEY = EncryptionKey(password=get_password())
        _KEYSTORE[_ENCRYPTION_KEY.salt] = _ENCRYPTION_KEY
    return _ENCRYPTION_KEY


def is_encrypted(filename: str) -> bool:
    """guess if the filename is an encrypted string"""
    # pylint: disable=broad-except
    try:
        # decrypt_filename(filename, password=get_password())
        filename = filename.replace(".", "=")
        b64_decoded = base64.urlsafe_b64decode(filename)
        if b64_decoded.startswith(MAGIC_FILENAME_HEADER):
            return True
        return False
    except Exception:
        # log.debug(f"guessing is_encrypted({filename}) -> False")
        return False


def report_event(event: str, *args: Any, **kwargs: Any) -> None:
    """
    reports events as they are happening from inside various
    functions for the purpose of progress monitoring
    """
    if STATUS_REPORTER is None or not isinstance(STATUS_REPORTER, StatusReporter):
        return
    STATUS_REPORTER.event(event, *args, **kwargs)
