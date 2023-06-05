""" Encrypt files and directories for backup on untrusted storage"""
import os

import base64
import logging
from contextlib import contextmanager
from typing import Self
import pathlib
import copy
from copy import deepcopy

# pylint: disable=logging-fstring-interpolation

# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)


SCRYPT_N = 2**14
BUFFER_SIZE_BYTES = 4 * 1024 * 1024
IV_SIZE_BYTES = 12
TAG_SIZE_BYTES = 16
SALT_SIZE_BYTES = 16

# file system limits
MAX_FILENAME_LENGTH = 255
MAX_PATH_LENGTH = 4096
BASE64_OVERHEAD = 1.5  # 50% overhead, 40 was too low
MAX_UNENCRYPTED_FILENAME_LENGTH = int(
    (MAX_FILENAME_LENGTH - IV_SIZE_BYTES - TAG_SIZE_BYTES - SALT_SIZE_BYTES)
    / BASE64_OVERHEAD
)
log.debug(f"Max unencrypted filename length: {MAX_UNENCRYPTED_FILENAME_LENGTH}")


_KEYSTORE = {}  # cached keys for detected salts


class FSFile:
    """File system file"""
    def __init__(self, name: str):
        self.name = name
        self.is_encrypted = is_encrypted(self.name)
        if self.is_encrypted:
            self.decrypted_name = decrypt_filename(self.name, password=get_password())
    
class FSDirectory:
    """File system directory"""
    def __init__(self, name: str, root:None|str = None):
        self.name = name
        self.root = root
        self.files = set()
        self.directories = set()
        self.is_encrypted = is_encrypted(self.name)
        if self.is_encrypted:
            self.decrypted_name = decrypt_filename(self.name, password=get_password())

    def add_directory(self, directory: Self):
        if directory.name in self.dir_names():
            # TODO: add tests for this
            raise ValueError(f"Directory {directory.name} already exists in {self.name}")
        self.directories.add(directory)
    
    def add_file(self, file: FSFile):
        self.files.add(file)
    
    def get_directory(self, name: str):
        for directory in self.directories:
            if directory.is_encrypted:
                if directory.decrypted_name == name:
                    return directory
            elif directory.name == name:
                return directory
        raise KeyError(f"Directory {name} not found")
    
    def is_empty(self):
        return len(self.files) == 0 and len(self.directories) == 0
    
    def dir_names(self):
        result = set()
        for d in self.directories:
            if d.is_encrypted:
                result.add(d.decrypted_name)
            else:
                result.add(d.name)
        return result
    
    def file_names(self):
        result = set()
        for f in self.files:
            if f.is_encrypted:
                result.add(f.decrypted_name)
            else:
                result.add(f.name)
        return result
    
    def __str__(self):
        return f"FSDirectory(name={self.name}, root={self.root}, encrypted={self.is_encrypted})"
        

    def pretty_print(self, indent: int = 2):
        """prints the directory structure"""
        print(self.dump(indent=indent))    

    def dump(self, indent: int=2):
        result = ""
        result+=f"{' ' * indent}{self.name} ({id(self)}) [root: {self.root}] {'(encrypted)' if self.is_encrypted else ''}\n"
        for directory in self.directories:
            result += directory.dump(indent=indent+2)
        for file in self.files:
            result+=f"{' ' * (indent+2)}{file.name} {'(encrypted)' if file.is_encrypted else ''}\n"
        return result

    @classmethod
    def from_filesystem(cls, path: str):
        """creates a directory tree from the file system"""
        if not safe_is_dir(path):
            raise IOError(f"Directory {path} does not exist or is not a directory")
        with safe_cwd_cm(path):
            _, dirs, files = next(os.walk("."))
            #log.debug(f"Content of {path}: dirs: {dirs} files: {files}")
        name = pathlib.Path(path).name
        parent = pathlib.Path(path).parent
        directory = cls(name=name, root=parent)
        for dname in dirs:
            directory.add_directory(cls.from_filesystem(os.path.join(path, dname)))
        for fname in files:
            directory.add_file(FSFile(name=fname))
        return directory

    def one_way_diff(self, other: Self) -> Self|None:
        """
        compares two directory trees
        returns a new FSDirectory with entries that are not in self
        and are in the other, including their parent elements if nested deeper.

        In other words returns new elements in the other.

        Returns None if the trees are identical
        """
        #TODO: tests!
        result = None
        
        for directory in other.directories:
            dir_name = directory.name if not directory.is_encrypted else directory.decrypted_name
            if dir_name not in self.dir_names():
                # if the directory is completely new, add the whole subtree from other
                subtree_copy = deepcopy(directory)
                if result is None:
                    # return copy of self without any nested elements (dirs, files)
                    result = self.__class__(name=self.name, root=self.root)
                result.add_directory(subtree_copy)
            else:
                # if the directory already exists, compare the subtrees
                subresult = self.get_directory(dir_name).one_way_diff(directory)
                if subresult:
                    if result is None:
                        result = self.__class__(name=self.name, root=self.root)
                    result.add_directory(subresult)

        for fname in other.file_names():
            filename = fname if not is_encrypted(fname) else decrypt_filename(fname, password=get_password())
            if filename not in self.file_names():
                if result is None:
                    result = self.__class__(name=self.name, root=self.root)
                result.add_file(copy.deepcopy(FSFile(name=fname)))
        
        return result

    

        


   

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


def get_safe_path_segments(path: str) -> list[str]:
    """splits path into segments that are below MAX_PATH_LENGTH"""
    path_segments = list(pathlib.Path(path).parts)
    safe_path_segments = []
    current_segment = ""
    for segment in path_segments:
        if (len(current_segment) + len(segment) + len("/")) > MAX_PATH_LENGTH:
            safe_path_segments.append(current_segment)
            current_segment = segment
        else:
            current_segment = os.path.join(current_segment, segment)
    safe_path_segments.append(current_segment)
    return safe_path_segments


class FileEncryptor:
    """File wrapper that encrypts the content of the file on the fly"""

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
            if len(self.path) > MAX_PATH_LENGTH:
                dirpath = os.path.dirname(self.path)
                filename = os.path.basename(self.path)
                safe_path_segments = get_safe_path_segments(dirpath)
                old_cwd = os.getcwd()
                for segment in safe_path_segments:
                    os.chdir(segment)
                self._fd = open(filename, "rb")
                for segment in get_safe_path_segments(old_cwd):
                    os.chdir(segment)

            else:
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

    def encrypt_to_file(self, destination, overwrite=False):
        """
        encrypts the underlying file and writes it to destination
        using incremental reads
        """
        directory = pathlib.Path(destination).parent
        filename = pathlib.Path(destination).name
        with safe_cwd_cm(str(directory)):
            if os.path.exists(filename) and not overwrite:
                raise IOError(
                    f"Destination file {destination} exists and overwrite is disabled."
                )
            with open(filename, "wb") as f:
                try:
                    while True:
                        data = self.read(BUFFER_SIZE_BYTES)
                        if not data:
                            break
                        f.write(data)
                except IOError as e:
                    log.error(f"Error encountered: {e}")
                    os.unlink(filename) # no not keep partial files present on the disk
                    raise


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
        dirname = str(pathlib.Path(path).parent)
        filename = str(pathlib.Path(path).name)
        with safe_cwd_cm(dirname):
            self.max_read_pos = (
                os.path.getsize(filename) - IV_SIZE_BYTES - TAG_SIZE_BYTES - SALT_SIZE_BYTES
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
        dirname = str(pathlib.Path(self.path).parent)
        filename = str(pathlib.Path(self.path).name)
        with safe_cwd_cm(dirname):
            self._fd = open(filename, "rb")
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
        self.crypto_init_done = True

    def read(self, size=None):
        """
        reads an encrypted underlying file and
        decrypts the file content, returns decrypted data
        """
        if not self.crypto_init_done:
            self._init_crypto()
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

    def decrypt_to_file(self, destination, overwrite=False):
        """
        decrypts the underlying file and writes it to destination
        using incremental reads
        """
        if os.path.exists(destination) and not overwrite:
            raise IOError(
                f"Destination file {destination} exists and overwrite is disabled."
            )
        if not self.crypto_init_done:
            self._init_crypto()
        dirname = str(pathlib.Path(destination).parent)
        filename = str(pathlib.Path(destination).name)
        with safe_cwd_cm(dirname):
            with open(filename, "wb") as f:
                while True:
                    data = self.read(BUFFER_SIZE_BYTES)
                    if not data:
                        break
                    f.write(data)

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
    if len(plaintext) > MAX_UNENCRYPTED_FILENAME_LENGTH:
        raise ValueError(
            f"Filename {plaintext} is too long ({len(plaintext)}). Max length is {MAX_UNENCRYPTED_FILENAME_LENGTH}."
        )
    iv, ciphertext, tag = _encrypt(key, plaintext.encode("utf-8"))
    result = base64.urlsafe_b64encode(iv + tag + key.salt + ciphertext)
    if len(result) > MAX_FILENAME_LENGTH:
        raise RuntimeError(
            f"Encrypted filename {result} is too long ({len(result)}). "
            f"Max length is {MAX_FILENAME_LENGTH}. This is a bug. "
            f"MAX_UNENCRYPTED_FILENAME_LENGTH={MAX_UNENCRYPTED_FILENAME_LENGTH} "
            "needs to be lowered."
        )
    return result


def decrypt_filename(encrypted_filename: bytes, password=None) -> str:
    """Decrypts a filename with the given key and returns a base64 encoded string"""
    # pylint: disable=invalid-name
    if password is None:
        raise NotImplementedError("Password must be provided")
    try:
        decoded = base64.urlsafe_b64decode(encrypted_filename)
    except Exception as ex:
        #log.error(f"Failed to decode filename {encrypted_filename}: {ex}")
        raise ValueError(f"Failed to decode filename {encrypted_filename}. Probably invalid (non-encrypted) filename for decryption?: {ex}")
    
    if len(decoded) < IV_SIZE_BYTES + TAG_SIZE_BYTES + SALT_SIZE_BYTES:
        raise ValueError(
            f"Invalid encrypted filename ({encrypted_filename}). Too short to get all required metadata."
        )
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
        log.debug(
            f"Generating decryption key for salt {salt}, triggered by {encrypted_filename}"
        )
        # TODO: ask for password interactively if not provided
        key = EncryptionKey(password=password, salt=salt)
        _KEYSTORE[salt] = key
    ciphertext = decoded[IV_SIZE_BYTES + TAG_SIZE_BYTES + SALT_SIZE_BYTES :]
    try:
        return _decrypt(key, iv, ciphertext, tag).decode("utf-8")
    except Exception as ex:
        #log.debug(f"Failed to decrypt filename {encrypted_filename}: {ex}")
        raise



def list_encrypted_directory(directory, password=None):
    """
    returns a tuple of
        (
            {'decrypted_dir_name': 'encrypted_dir_name,...},
            {'decrypted_file_name': 'encrypted_file_name,...},
    """
    # TODO: ask for password interactively if not provided
    # TODO: add tests
    if password is None:
        raise NotImplementedError("Password must be provided")
    encrypted_dirs = {}
    encrypted_files = {}
    with safe_cwd_cm(directory):
        for root, dirs, files in os.walk("."):
            root = directory
            for dname in dirs:
                # TODO: error handling for invalid (=unecrypted) filenames
                decrypted_name = decrypt_filename(dname, password=password)
                if decrypted_name in encrypted_dirs:
                    log.error(
                        f"Duplicate directory name {decrypted_name} -> {dname} in {root}. Probably identical file encrypted with multiple keys."
                    )
                encrypted_dirs[decrypted_name] = dname
            for fname in files:
                decrypted_name = decrypt_filename(fname, password=password)
                if decrypted_name in encrypted_files:
                    log.error(
                        f"Duplicate file name {decrypted_name} -> {fname} in {root}. Probably identical file encrypted with multiple keys."
                    )
                encrypted_files[decrypted_name] = fname
            break  # fist level only
    return (encrypted_dirs, encrypted_files)


    

def safe_makedirs(dirpath: str, exist_ok: bool = False):
    """creates diretories even if the path is longer than MAX_PATH_LENGTH"""
    path = pathlib.Path(dirpath)
    root = str(path.parent)
    directory = str(path.name)
    if len(path.parts) < 2:
        raise ValueError(f"Invalid path: {dirpath}")
    old_cwd = os.getcwd()
    if len(dirpath) > MAX_PATH_LENGTH:
        segments = get_safe_path_segments(root)
        for segment in segments:
            os.makedirs(segment, exist_ok=exist_ok)
            os.chdir(segment)
        os.makedirs(directory, exist_ok=exist_ok)
    else:
        os.makedirs(dirpath, exist_ok=exist_ok)
    safe_cwd(old_cwd)


def safe_is_dir(path: str):
    """returns True if path is a directory, even if the path is longer than MAX_PATH_LENGTH"""
    with safe_cwd_cm(os.getcwd()):
        if len(path) > MAX_PATH_LENGTH:
            segments = get_safe_path_segments(path)
            for segment in segments:
                if not os.path.isdir(segment):
                    return False
                os.chdir(segment)
            return True
        else:
            return os.path.isdir(path)


def encrypt_directory(source, destination, password):
    """encrypts all files and directories in directory and writes them to destination"""
    log.debug(f"encrypt_directory({source} -> {destination})")
    safe_makedirs(destination, exist_ok=True)
    key = EncryptionKey(password=password)
    if not safe_is_dir(source):
        raise ValueError(f"Directory {source} does not exist or is not a directory")
    with safe_cwd_cm(source):
        for root, dirs, files in os.walk("."):
            root = source
            existing_dirs, existing_files = list_encrypted_directory(
                destination, password=password
            )
            log.debug(f"Source dirs in [{source}]: {dirs} Source files: {files}")
            log.debug(
                f"Existing encrypted dirs in [{destination}]: {existing_dirs} Existing files: {existing_files}"
            )

            for fname in files:
                if fname in existing_files:
                    log.debug(
                        f"Skipping already encrypted file {fname} -> {existing_files[fname]}"
                    )
                    continue
                encrypted_filename = encrypt_filename(key, fname).decode("utf-8")
                abs_fname = os.path.join(root, fname)
                abs_enc_fname = os.path.join(destination, encrypted_filename)
                log.debug(f"Encrypting file {fname} -> {encrypted_filename}")
                file_encryptor = FileEncryptor(abs_fname, key)
                file_encryptor.encrypt_to_file(os.path.join(destination, abs_enc_fname))
                file_encryptor.close()
            for dname in dirs:
                abs_dname = os.path.join(root, dname)
                if dname in existing_dirs:
                    log.debug(
                        f"Skipping already encrypted directory {dname} -> {existing_dirs[dname]}"
                    )
                    abs_enc_dname = os.path.join(destination, existing_dirs[dname])
                else:
                    encrypted_dirname = encrypt_filename(key, dname).decode("utf-8")
                    abs_enc_dname = os.path.join(destination, encrypted_dirname)
                    log.debug(
                        f"Encrypting directory {dname} {len(dname)} -> "
                        f"{encrypted_dirname} {len(encrypted_dirname)}"
                    )
                    with safe_cwd_cm(destination):
                        os.mkdir(encrypted_dirname)
                encrypt_directory(
                    source=abs_dname, destination=abs_enc_dname, password=password
                )
            break  # one level in each call, the rest gets handled in the recurisve calls


def safe_cwd(directory: str):
    """Changes to a directory that is over MAX_PATH_LENGTH"""
    if len(directory) > MAX_PATH_LENGTH:
        segments = get_safe_path_segments(directory)
        for segment in segments:
            os.chdir(segment)
        if not os.getcwd() == directory:
            raise RuntimeError(
                f"Failed to change to directory {directory}, cwd is {os.getcwd()}, segments: {segments}"
            )
    else:
        os.chdir(directory)


@contextmanager
def safe_cwd_cm(directory: str):
    """
    Context manager:
    changes to a directory that is over MAX_PATH_LENGTH
    and then back
    """
    try:
        old_cwd = os.getcwd()
    except FileNotFoundError:
        # sometimes we are in a directory that no longer exists ;)
        log.warning("Current working directory no longer exists, will return to /")
        old_cwd = "/"
    try:
        safe_cwd(directory)
        yield
    finally:
        safe_cwd(old_cwd)


def decrypt_directory(source, destination, password):
    """decrypts all files and directories in directory and writes them to destination"""
    log.debug(f"decrypt_directory({source} -> {destination})")
    safe_makedirs(destination, exist_ok=True)
    if not safe_is_dir(source):
        raise ValueError(f"Directory {source} does not exist or is not a directory")
    with safe_cwd_cm(source):
        for root, dirs, files in os.walk("."):
            root = source # override due to cwd context manager
            with safe_cwd_cm(destination):
                _, existing_dirs, existing_files = next(os.walk("."))
            log.debug(f"Source dirs in [{source}]: {dirs} Source files: {files}")
            log.debug(
                f"Existing decrypted dirs in [{destination}]: {existing_dirs} Existing files: {existing_files}"
            )
            for fname in files:
                decrypted_filename = decrypt_filename(fname, password=password)
                if decrypted_filename in existing_files:
                    log.debug(
                        f"Skipping already decrypted file {fname} -> {decrypted_filename}"
                    )
                    continue
                abs_fname = os.path.join(root, fname)
                abs_dec_fname = os.path.join(destination, decrypted_filename)
                log.debug(f"Decrypting file {fname} -> {decrypted_filename}")
                file_decryptor = FileDecryptor(abs_fname, password=password)
                file_decryptor.decrypt_to_file(os.path.join(destination, abs_dec_fname))
                file_decryptor.close()
            for dname in dirs:
                abs_dname = os.path.join(root, dname)
                decrypted_dirname = decrypt_filename(dname, password=password)
                if decrypted_dirname in existing_dirs:
                    log.debug(
                        f"Skipping already decrypted directory {dname} -> {decrypted_dirname}"
                    )
                    abs_dec_dname = os.path.join(destination, decrypted_dirname)
                else:
                    abs_dec_dname = os.path.join(destination, decrypted_dirname)
                    log.debug(f"Decrypting directory {dname} -> {decrypted_dirname}")
                    with safe_cwd_cm(destination):
                        os.mkdir(decrypted_dirname)
                decrypt_directory(
                    source=abs_dname, destination=abs_dec_dname, password=password
                )
            break  # one level in each call, the rest gets handled in the recurisve calls

def compare_directories(source: str, destination: str, password: str):
    """compares two directories, non-recursive"""
    source_is_encrypted = False
    destination_is_encrypted = True
    if not safe_is_dir(source):
        raise IOError(f"Directory {source} does not exist or is not a directory")
    if not safe_is_dir(destination):
        raise IOError(
            f"Directory {destination} does not exist or is not a directory"
        )
    with safe_cwd_cm(source):
        _, source_dirs, source_files = next(os.walk("."))   
        log.debug(f"Source content {source}: dirs: {source_dirs} files: {source_files}")
    with safe_cwd_cm(destination):
        encrypted_content = list_encrypted_directory(destination, password=password)
        destination_dirs = list(encrypted_content[0].keys())
        destination_files = list(encrypted_content[1].keys())
        
        log.debug(f"Destination content {destination}: dirs: [{destination_dirs}] files: {destination_files}")
    
    result = {
        "source_new":[],
        "source_missing":[],
        "destination_new":[],
        "destination_missing":[],
    }
    for dname in source_dirs:
        if dname not in destination_dirs:
            result["source_new"].append(dname)
    for fname in source_files:
        if fname not in destination_files:
            result["source_new"].append(fname)
    for dname in destination_dirs:
        if dname not in source_dirs:
            result["destination_new"].append(dname)
    for fname in destination_files:
        if fname not in source_files:
            result["destination_new"].append(fname)
    log.debug(f"Comparison result: {result}")
    return result

def create_fs_tree(root: str) -> FSDirectory:
    """ creates a dictionary of the file system tree below root (recursively) """
    if not safe_is_dir(root):
        raise IOError(f"Directory {root} does not exist or is not a directory")
    with safe_cwd_cm(root):
        _, dirs, files = next(os.walk("."))
        log.debug(f"Content of {root}: dirs: {dirs} files: {files}")
    fs_root = FSDirectory(name=root, root=root)
    for dname in dirs:
        fs_root.add_directory(create_fs_tree(os.path.join(root, dname)))
    for fname in files:
        fs_root.add_file(FSFile(name=fname))
    return fs_root


def get_password():
    """asks for password interactively"""
    #password = getpass.getpass(prompt="Password: ")
    return "test"

def is_encrypted(filename: str):
    """ guess if the filename is an encrypted string"""
    try:
        decrypt_filename(filename, password=get_password())
        #log.debug(f"guessing is_encrypted({filename}) -> True")
        return True
    except Exception:
        #log.debug(f"guessing is_encrypted({filename}) -> False")
        return False
    
        


if __name__ == "__main__":
    # encrypt_directory(
    #     "/tmp/backup_test/source", "/tmp/backup_test/encrypted", password="test"
    # )

    # decrypt_directory(
    #     "/tmp/backup_test/encrypted", "/tmp/backup_test/decrypted", password="test"
    # )
    
    #compare_directories("/tmp/backup_test/source", "/tmp/backup_test/encrypted", password="test")
    # encrypt_directory(
    #     "/tmp/backup_test/source-new", "/tmp/backup_test/encrypted", password="test"
    # )
    root1 = FSDirectory.from_filesystem("/data/tmp/test/root-01")
    # encrypt_directory("/data/tmp/test/root-01", "/data/tmp/test/encrypted-01", password="test")
    encrypted = FSDirectory.from_filesystem("/data/tmp/test/encrypted-01")
    encrypted.pretty_print()
    diff = root1.one_way_diff(encrypted)
    if diff:
        diff.pretty_print()
    else:
        print("Trees are identical")

    diff2 = encrypted.one_way_diff(root1)
    if diff2:
        diff2.pretty_print()
    else:
        print("Trees are identical")

    

#TODO: next - projit jeste diff logiku a zcela ji porozumet, abych ji mohl verit
#TODO: pak zacit psat testy 