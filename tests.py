""" Unit tests for backup tool """
import base64
import logging
import os
import random
import shutil
import string
import tempfile
import pathlib
import unittest
import subprocess
import glob
from copy import deepcopy
from unittest.mock import Mock, patch

import base
from base import EncryptionKey, FSDirectory, FSFile
from filesystems import RealFilesystem, VirtualFilesystem

base.log.setLevel(base.logging.CRITICAL)

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)


# pylint: disable=logging-fstring-interpolation
# pylint: disable=too-many-lines
# pylint: disable=too-many-locals
# pylint: disable=too-many-statements
# no typing checks for tests (yet?)
# mypy: ignore-errors

base.get_password = Mock(return_value="test")

REAL_FS = RealFilesystem()
VIRT_FS = VirtualFilesystem()

# use weaker scrypt parameters for testing
base.SCRYPT_N = 2**14


def create_fs_tree(root, depth=2, files_per_dir=3, dirs_per_dir=2):
    """Create a directory tree for testing"""
    for i in range(files_per_dir):
        fname = os.path.join(root, f"file-{depth}-{i}")
        with open(fname, "w", encoding="utf-8") as tfd:
            tfd.write(fname)
    for i in range(dirs_per_dir):
        dname = os.path.join(root, f"dir-{depth}-{i}")
        os.mkdir(dname)
        if depth > 0:
            create_fs_tree(
                root=dname,
                depth=depth - 1,
                files_per_dir=files_per_dir,
                dirs_per_dir=dirs_per_dir,
            )


def create_fs_tree_from_dict(root, tree):
    """
    Create a directory tree for testing from a dictionary.
    Dictionary format: {filename: content} or {dirname: {filename: content}},
    nested: {dirname: {dirname: {filename: content}}}

    """
    for name, content in tree.items():
        if isinstance(content, dict):
            dname = os.path.join(root, name)
            os.mkdir(dname)
            create_fs_tree_from_dict(dname, content)
        else:
            fname = os.path.join(root, name)
            with open(fname, "w", encoding="utf-8") as tfd:
                tfd.write(content)


class EncryptionKeyTest(unittest.TestCase):
    """Test encryption key class"""

    def test_new_key(self):
        """Test creation of new key"""
        password = "test"
        key = EncryptionKey(password=password)
        self.assertEqual(len(key.key), 32)
        self.assertEqual(len(key.salt), base.SALT_SIZE_BYTES)

    def test_key_from_salt(self):
        """Test creation of key from salt"""
        password = "test"
        key = EncryptionKey(password=password)
        key2 = EncryptionKey(password=password, salt=key.salt)
        self.assertEqual(key.key, key2.key)
        self.assertEqual(key.salt, key2.salt)


class FileEncryptorTest(unittest.TestCase):
    """Test file encryption"""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="backup_test_")
        self.test_file = self.get_temp_file()
        self.test_data = b"test" * 1024 * 1024
        with open(self.test_file, "wb") as tfd:
            tfd.write(self.test_data)
        self.filesystem = REAL_FS

    def get_temp_file(self, prefix=""):
        """Get a temporary file path"""
        # pylint: disable=invalid-name
        fd, path = tempfile.mkstemp(dir=self.test_dir, prefix=prefix)
        os.close(fd)
        return path

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_encrypt_file(self):
        """Test encryption of file"""
        key = base.get_key()
        # encrypt buffered
        encryptor = base.FileEncryptor(
            path=self.test_file, key=key, filesystem=self.filesystem
        )
        encrypted_data = b""
        buffer_size = 1024 * 10
        while True:
            new_data = encryptor.read(buffer_size)
            if not new_data:
                break
            encrypted_data += new_data
        encryptor.close()
        # encrypt all at once with new instance
        encryptor = base.FileEncryptor(
            path=self.test_file, key=key, filesystem=self.filesystem
        )
        encrypted_data_unbuf = encryptor.read()
        encryptor.close()
        # compare the size of the encrypted data, content will differ
        # due to the random IV
        self.assertEqual(len(encrypted_data), len(encrypted_data_unbuf))

    def test_decrypt_file(self):
        """Test decryption of file"""
        key = base.get_key()
        enc_buf = base.FileEncryptor(
            path=self.test_file, key=key, filesystem=self.filesystem
        )
        enc_buf_file = self.get_temp_file()
        buffer_size = 1024 * 10
        with self.filesystem.open(enc_buf_file, "wb") as tfd:
            while True:
                data = enc_buf.read(buffer_size)
                if not data:
                    break
                tfd.write(data)
        enc_buf.close()
        enc_unbuf = base.FileEncryptor(
            path=self.test_file, key=key, filesystem=self.filesystem
        )
        enc_unbuf_file = self.get_temp_file()
        with self.filesystem.open(enc_unbuf_file, "wb") as tfd:
            while True:
                data = enc_unbuf.read()
                if not data:
                    break
                tfd.write(data)
        enc_unbuf.close()

        # decrypt
        dec_buf = base.FileDecryptor(path=enc_buf_file, filesystem=self.filesystem)
        dec_buf_data = b""
        while True:
            new_data = dec_buf.read(buffer_size)
            if not new_data:
                break
            dec_buf_data += new_data
        dec_buf.close()
        dec_unbuf = base.FileDecryptor(path=enc_unbuf_file, filesystem=self.filesystem)
        dec_unbuf_data = dec_unbuf.read()
        dec_unbuf.close()
        self.assertEqual(
            dec_buf_data,
            dec_unbuf_data,
            "Buffered and unbuffered decryption do not match",
        )
        self.assertEqual(
            dec_buf_data, self.test_data, "Decrypted data does not match original data"
        )

    def test_encrypt_to_file(self):
        """Test encryption of file to file"""
        key = base.get_key()
        enc_file = self.get_temp_file()
        enc = base.FileEncryptor(
            path=self.test_file, key=key, filesystem=self.filesystem
        )
        enc.encrypt_to_file(enc_file, filesystem=self.filesystem, overwrite=True)
        enc.close()
        # decrypt
        dec = base.FileDecryptor(path=enc_file, filesystem=self.filesystem)
        dec_data = dec.read()
        dec.close()
        self.assertEqual(
            dec_data, self.test_data, "Decrypted data does not match original data"
        )

    def test_invalid_data_decryption(self):
        """Test decryption of invalid data"""
        key = base.get_key()
        enc_file = self.get_temp_file()
        enc = base.FileEncryptor(
            path=self.test_file, key=key, filesystem=self.filesystem
        )
        enc.encrypt_to_file(enc_file, filesystem=self.filesystem, overwrite=True)
        enc.close()
        # corrupt data
        with self.filesystem.open(enc_file, "r+b") as tfd:
            tfd.seek(0)
            tfd.write(b"invalid")
        # decrypt buffered
        dec = base.FileDecryptor(path=enc_file, filesystem=self.filesystem)
        dec_data = b""
        buffer_size = 1024 * 10
        with self.assertRaises(base.DecryptionError):
            while True:
                new_data = dec.read(buffer_size)
                if not new_data:
                    break
                dec_data += new_data
        dec.close()
        # decrypt unbuffered
        dec = base.FileDecryptor(path=enc_file, filesystem=self.filesystem)
        with self.assertRaises(base.DecryptionError):
            dec_data = dec.read()
        dec.close()

    def test_plaintext_not_in_encrypted_data(self):
        """Test that the plaintext is not in the encrypted data"""
        key = base.get_key()
        encryptor = base.FileEncryptor(
            path=self.test_file, key=key, filesystem=self.filesystem
        )
        encrypted_data = encryptor.read()
        encryptor.close()
        self.assertNotEqual(encrypted_data, self.test_data)
        self.assertNotIn(self.test_data[:20], encrypted_data)

    def test_decrypt_empty_file(self):
        """Test decryption of empty file"""
        enc_file = self.get_temp_file()
        with self.assertRaises(IOError):
            base.FileDecryptor(path=enc_file, filesystem=self.filesystem)

    def test_encrypt_existing_file_overwrite(self):
        """Test encryption of existing file with overwrite flag"""
        key = base.get_key()
        orig_data = b"original data"
        enc_file = self.get_temp_file()
        with self.filesystem.open(enc_file, "wb") as tfd:
            tfd.write(orig_data)
        enc = base.FileEncryptor(
            path=self.test_file, key=key, filesystem=self.filesystem
        )
        dest_file = self.get_temp_file()
        with self.assertRaises(OSError):
            enc.encrypt_to_file(dest_file, filesystem=self.filesystem)
        enc.close()
        enc = base.FileEncryptor(
            path=self.test_file, key=key, filesystem=self.filesystem
        )
        enc.encrypt_to_file(dest_file, filesystem=self.filesystem, overwrite=True)
        enc.close()
        with self.filesystem.open(dest_file, "rb") as tfd:
            enc_data = tfd.read()
        self.assertNotEqual(orig_data, enc_data)

    def test_decrypt_existing_file_overwrite(self):
        """Test decryption of existing file with overwrite flag"""
        key = base.get_key()
        enc_file = self.get_temp_file()
        enc = base.FileEncryptor(
            path=self.test_file, key=key, filesystem=self.filesystem
        )
        enc.encrypt_to_file(enc_file, filesystem=self.filesystem, overwrite=True)
        enc.close()
        dec = base.FileDecryptor(path=enc_file, filesystem=self.filesystem)
        dest_file = self.get_temp_file()
        orig_data = b"original data"
        with self.filesystem.open(dest_file, "wb") as tfd:
            tfd.write(orig_data)
        with self.assertRaises(OSError):
            dec.decrypt_to_file(dest_file, filesystem=self.filesystem)
        dec.close()
        dec = base.FileDecryptor(path=enc_file, filesystem=self.filesystem)
        dec.decrypt_to_file(dest_file, filesystem=self.filesystem, overwrite=True)
        dec.close()
        with self.filesystem.open(dest_file, "rb") as tfd:
            dec_data = tfd.read()
        self.assertNotEqual(orig_data, dec_data)

    def test_filename_too_long_for_encryption(self):
        """Test that a filename that is too long for encryption raises an error"""
        filename = "x" * (base.MAX_FILENAME_LENGTH + 1)
        key = base.get_key()
        with self.assertRaises(ValueError):
            base.encrypt_filename(key, filename)

    @patch(
        "filesystems.RealFilesystem.get_size", Mock(return_value=base.MAX_FILE_SIZE + 1)
    )
    @patch(
        "filesystems.VirtualFilesystem.get_size",
        Mock(return_value=base.MAX_FILE_SIZE + 1),
    )
    def test_file_too_big_to_encrypt(self):
        """Tests that encryption attempt of too large file raises an error"""
        key = base.get_key()
        encryptor = base.FileEncryptor(
            path=self.test_file, key=key, filesystem=self.filesystem
        )
        with self.assertRaises(
            IOError,
            msg="File encryption of file bigger than limit did not raise an error",
        ):
            encryptor.encrypt_to_file(
                os.path.join(self.test_dir, "test.enc"),
                filesystem=self.filesystem,
                overwrite=True,
            )

        encryptor.close()

    def test_encrypt_to_file_with_oversized_path(self):
        """
        test encryption with path that exceeds usual
        max path limit (4096b)
        """
        oversize_path_length = 4096 + 1024
        max_path_root = self.test_dir
        _iter = 0
        while len(max_path_root) < oversize_path_length:
            max_path_root = os.path.join(max_path_root, f"{_iter:03d}-dir")
            _iter += 1
        self.filesystem.makedirs(max_path_root)
        source_dir = os.path.join(max_path_root, "source")
        encrypted_dir = os.path.join(max_path_root, "encrypted")
        self.filesystem.mkdir(source_dir)
        self.filesystem.mkdir(encrypted_dir)
        # create a test file
        test_file = os.path.join(source_dir, "test.txt")
        target_file = os.path.join(encrypted_dir, "test.txt")
        with self.filesystem.open(test_file, "wb") as tfd:
            tfd.write(b"test")
        # encrypt using to_file
        key = base.get_key()
        encryptor = base.FileEncryptor(
            path=test_file, key=key, filesystem=self.filesystem
        )
        encryptor.encrypt_to_file(target_file, filesystem=self.filesystem)
        encryptor.close()


class FileNameEncryptionTest(unittest.TestCase):
    """Test encryption of filenames"""

    def test_encrypt_filename(self):
        """Test encryption of filename"""
        key = base.get_key()
        filename = "test.txt"
        encrypted_name = base.encrypt_filename(key, filename)
        self.assertNotEqual(filename, encrypted_name)
        self.assertEqual(filename, base.decrypt_filename(encrypted_name))

    def test_decrypt_corrupted_filename(self):
        """Test decryption of corrupted filename"""
        key = base.get_key()
        filename = "test.txt"
        encrypted_name = base.encrypt_filename(key, filename)
        encrypted_name = encrypted_name.replace(b".", b"=")
        raw = base64.urlsafe_b64decode(encrypted_name)
        raw = raw[:10] + b"INVALID" + raw[10:]
        encrypted_name = base64.urlsafe_b64encode(raw)
        encrypted_name = encrypted_name.replace(b"=", b".")

        with self.assertRaises(base.DecryptionError):
            base.decrypt_filename(encrypted_name)

    def test_decrypt_too_short(self):
        """Test decryption of too short filename"""
        filename = b"test"
        invalid_crypto_data = base64.urlsafe_b64encode(filename)
        with self.assertRaises(ValueError):
            base.decrypt_filename(invalid_crypto_data)

    def test_filename_too_long(self):
        """Test that a filename that is too long for encryption raises an error"""
        filename = "x" * (base.MAX_UNENCRYPTED_FILENAME_LENGTH + 1)
        with self.assertRaises(ValueError):
            base.encrypt_filename(base.get_key(), filename)

    def test_filename_at_max_length(self):
        """Test that a filename at the max length is encrypted"""
        filename = "x" * base.MAX_UNENCRYPTED_FILENAME_LENGTH
        key = base.get_key()
        encrypted = base.encrypt_filename(key, filename)
        self.assertNotEqual(filename, encrypted)
        self.assertEqual(filename, base.decrypt_filename(encrypted))
        self.assertLessEqual(len(encrypted), base.MAX_FILENAME_LENGTH)

    def test_insecure_filename_decryption(self):
        """Tests that unsafe filenames are not passed from decryption routine"""
        harmful_filename = "../../something-important"
        encrypted = base.encrypt_filename(base.get_key(), harmful_filename)
        with self.assertRaises(ValueError):
            base.decrypt_filename(encrypted)


class DirectoryEncryptionTest(unittest.TestCase):
    """Test encryption of directories"""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="backup-test-")
        self.source_dir = os.path.join(self.root, "source")
        self.encrypted_dir = os.path.join(self.root, "encrypted")
        self.decrypted_dir = os.path.join(self.root, "decrypted")
        self.cwd = os.getcwd()
        os.mkdir(self.source_dir)
        os.mkdir(self.encrypted_dir)
        os.mkdir(self.decrypted_dir)

    def tearDown(self):
        shutil.rmtree(self.root)
        # return back to original, as some of our tests might change
        # the cwd and delete it afterwards
        os.chdir(self.cwd)

    def test_encrypt_decrypt_file(self):
        """test for encrypt_file and decrypt_file base methods"""
        source_file = os.path.join(self.source_dir, "test.txt")
        random_file = os.path.join(self.source_dir, "random.txt")

        with open(source_file, "wb") as tfd:
            tfd.write(b"test")
        with open(random_file, "wb") as tfd:
            tfd.write(b"test")
        # dirs not accepted
        with self.assertRaises(ValueError):
            base.encrypt_file(self.source_dir, REAL_FS, self.encrypted_dir, REAL_FS)
        # target must be a dir
        with self.assertRaises(ValueError):
            base.encrypt_file(source_file, REAL_FS, random_file, REAL_FS)
        # encrypt
        enc_fname = base.encrypt_file(source_file, REAL_FS, self.encrypted_dir, REAL_FS)

        # source must not be a dir
        with self.assertRaises(ValueError):
            base.decrypt_file(self.encrypted_dir, REAL_FS, self.decrypted_dir, REAL_FS)
        # target must be a dir
        with self.assertRaises(ValueError):
            base.decrypt_file(
                os.path.join(self.encrypted_dir, enc_fname),
                REAL_FS,
                random_file,
                REAL_FS,
            )

        # decrypt
        base.decrypt_file(
            os.path.join(self.encrypted_dir, enc_fname),
            REAL_FS,
            self.decrypted_dir,
            REAL_FS,
        )
        self.assertTrue(os.path.exists(os.path.join(self.decrypted_dir, "test.txt")))

    def test_fsdirectory_listings_and_paths(self):
        """test FSDirectory.abs_decrypted_path and to_path_list"""
        tree = {
            "dir1": {"dir-1-1": {}, "dir-1-2": {"file-1-2": "test"}, "file1": "test"},
            "dir2": {"file2": "test2"},
            "file3": "test3",
        }
        create_fs_tree_from_dict(self.source_dir, tree)
        fs_dir = FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS)
        list_items = fs_dir.to_path_list()
        unencrypted_paths = [_[0] for _ in list_items]
        self.assertEqual(len(list_items), 8)
        for item in list_items:
            # not encrypted, both paths should be equal
            self.assertEqual(item[0], item[1])
        enc_dir = FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS)
        base.encrypt_directory(fs_dir, enc_dir)
        # reread
        enc_dir = FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS)
        list_items = enc_dir.to_path_list()
        self.assertEqual(len(list_items), 8)
        for item in list_items:
            # not encrypted, both paths should be equal
            self.assertNotEqual(item[0], item[1])

        encrypted_plain_paths = [_[0] for _ in list_items]
        # no new paths, no path missing
        self.assertEqual(
            sorted([_.replace(self.source_dir, "") for _ in unencrypted_paths]),
            sorted([_.replace(self.encrypted_dir, "") for _ in encrypted_plain_paths]),
        )
        # check for correctness
        for item in list_items:
            # make sure that the paths actually exist
            self.assertTrue(
                os.path.exists(item[0].replace(self.encrypted_dir, self.source_dir)),
            )
            self.assertTrue(os.path.exists(item[1]))
        # compare the result to the actual filesystem
        pathlist = list(map(str, pathlib.Path(self.source_dir).glob("**/*")))
        for path in pathlist:
            self.assertIn(path, unencrypted_paths)

    def test_encrypt_empty_directory(self):
        """Test encryption of empty directory"""
        base.encrypt_directory(
            FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
        )
        _, dirs, files = next(os.walk(self.encrypted_dir))
        self.assertEqual(dirs, [])
        self.assertEqual(files, [])

    def test_encrypt_directory(self):
        """Test encryption of directory"""
        create_fs_tree(self.source_dir)
        base.encrypt_directory(
            FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
        )
        # check that number of files on each level is the same
        # and that the content is not the same (i.e. encrypted)
        source_walker = os.walk(self.source_dir)
        encrypted_walker = os.walk(self.encrypted_dir)
        while True:
            try:
                source_root, source_dirs, source_files = next(source_walker)
                source_dirs.sort()
                source_files.sort()
                encrypted_root, encrypted_dirs, encrypted_files = next(encrypted_walker)
                encrypted_dirs.sort()
                encrypted_files.sort()
            except StopIteration:
                break
            self.assertEqual(len(source_files), len(encrypted_files))
            self.assertEqual(len(source_dirs), len(encrypted_dirs))
            for source_file, encrypted_file in zip(source_files, encrypted_files):
                with open(os.path.join(source_root, source_file), "rb") as tfd:
                    source_data = tfd.read()
                with open(os.path.join(encrypted_root, encrypted_file), "rb") as tfd:
                    encrypted_data = tfd.read()
                self.assertNotEqual(
                    source_data, encrypted_data, "Source data found in encrypted file"
                )

    def test_decrypt_directory(self):
        """encrypt, decrypt and compare with source for one-to-one match across the tree"""
        create_fs_tree(self.source_dir)
        base.encrypt_directory(
            FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
        )
        base.decrypt_directory(
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.decrypted_dir, filesystem=REAL_FS),
        )
        source_walker = os.walk(self.source_dir)
        decrypted_walker = os.walk(self.decrypted_dir)
        while True:
            try:
                source_root, source_dirs, source_files = next(source_walker)
                source_dirs.sort()
                source_files.sort()
                decrypted_root, decrypted_dirs, decrypted_files = next(decrypted_walker)
                decrypted_dirs.sort()
                decrypted_files.sort()
            except StopIteration:
                break
            self.assertEqual(len(source_files), len(decrypted_files))
            self.assertEqual(len(source_dirs), len(decrypted_dirs))
            for source_file, decrypted_file in zip(
                sorted(source_files), sorted(decrypted_files)
            ):
                with open(os.path.join(source_root, source_file), "rb") as tfd:
                    source_data = tfd.read()
                with open(os.path.join(decrypted_root, decrypted_file), "rb") as tfd:
                    decrypted_data = tfd.read()
                self.assertEqual(
                    source_data,
                    decrypted_data,
                    f"Decrypted data does not match source "
                    f"{os.path.join(source_root, source_file)} vs "
                    f"{os.path.join(decrypted_root, decrypted_file)}",
                )

    def test_structures_larger_than_max_path_limits(self):
        """
        Test that structures larger than the maximum
        path length are handled correctly
        """
        source_dir = tempfile.mkdtemp(dir=self.root, prefix="source-")
        dest_dir = tempfile.mkdtemp(dir=self.root, prefix="encrypted-")
        dec_dir = tempfile.mkdtemp(dir=self.root, prefix="decrypted-")
        current_path_length = len(source_dir)
        dir_name_size = base.MAX_UNENCRYPTED_FILENAME_LENGTH  # length of directory name
        # long enough but not too much for os.makedirs
        depth = int((base.MAX_PATH_LENGTH - current_path_length) / dir_name_size) - 1
        dirtree = "/".join(
            [str(_) + "x" * (dir_name_size - len(str(_))) for _ in range(depth)]
        )
        last_dir = os.path.join(source_dir, dirtree)
        os.makedirs(last_dir)
        filename = "f" * base.MAX_UNENCRYPTED_FILENAME_LENGTH
        os.chdir(last_dir)
        os.makedirs(dirtree)  # double the "long enough", so it's definitely too much :)
        os.chdir(dirtree)
        log.debug(f"Current dir length: {len(os.getcwd())}")
        with open(filename, "wb") as tfd:
            tfd.write(b"test")
        abs_filename = os.path.join(os.getcwd(), filename)
        log.debug(f"Abs path length of test filename: {len(abs_filename)}")
        base.encrypt_directory(
            FSDirectory.from_filesystem(source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(dest_dir, filesystem=REAL_FS),
        )
        base.decrypt_directory(
            FSDirectory.from_filesystem(dest_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(dec_dir, filesystem=REAL_FS),
        )

        source_walker = os.walk(source_dir)
        decrypted_walker = os.walk(dec_dir)
        while True:
            try:
                source_root, source_dirs, source_files = next(source_walker)
                source_dirs.sort()
                source_files.sort()
                decrypted_root, decrypted_dirs, decrypted_files = next(decrypted_walker)
                decrypted_dirs.sort()
                decrypted_files.sort()
            except StopIteration:
                break
            self.assertEqual(
                len(source_files),
                len(decrypted_files),
                "Number of files in source and decrypted directory does not match",
            )
            self.assertEqual(
                len(source_dirs),
                len(decrypted_dirs),
                "Number of directories in source and decrypted directory does not match",
            )
            for source_file, decrypted_file in zip(source_files, decrypted_files):
                with open(os.path.join(source_root, source_file), "rb") as tfd:
                    source_data = tfd.read()
                with open(os.path.join(decrypted_root, decrypted_file), "rb") as tfd:
                    decrypted_data = tfd.read()
                self.assertEqual(
                    source_data, decrypted_data, "Decrypted data does not match source"
                )

    def test_special_files_exclusion(self):
        """Test that special files are excluded from encryption"""

        os.mkdir(os.path.join(self.source_dir, "regulardir"))
        with open(os.path.join(self.source_dir, "regularfile"), "wb") as tfd:
            tfd.write(b"test")
        # create symlink to file and directory
        os.symlink(
            os.path.join(self.source_dir, "regulardir"),
            os.path.join(self.source_dir, "symlinkdir"),
        )
        os.symlink(
            os.path.join(self.source_dir, "regularfile"),
            os.path.join(self.source_dir, "symlinkfile"),
        )
        # create fifo
        os.mkfifo(os.path.join(self.source_dir, "fifo"))
        # fifo and symlinks are enough
        base.encrypt_directory(
            FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
        )
        edir = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertEqual(
            len(edir.file_names()), 1, "Non-regular files were not excluded."
        )
        self.assertEqual(
            len(edir.dir_names()), 1, "Non-regular directories were not excluded."
        )

    def test_encrypt_the_same_tree_twice_to_the_same_dest(self):
        """Test that encrypting the same tree twice to the same destination
        does not create extra encrypted content (i.e. the same file under
        a new encrypted name)
        """
        create_fs_tree(self.source_dir)
        base.encrypt_directory(
            FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
        )
        tree_content = list(os.walk(self.encrypted_dir))
        base.encrypt_directory(
            FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
        )
        tree_content2 = list(os.walk(self.encrypted_dir))
        self.assertEqual(
            tree_content,
            tree_content2,
            "Encrypted content changed on second run, "
            "some files were probably not properly skipped.",
        )

    def test_garbage_in_encrypted_dir(self):
        """tests behaviour when encrypted dir contains non-encrypted files"""
        create_fs_tree(self.source_dir)
        base.encrypt_directory(
            FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
        )
        with open(os.path.join(self.encrypted_dir, "garbage"), "wb") as tfd:
            tfd.write(b"test")
        # re-encryption should not fail
        base.encrypt_directory(
            FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
        )
        enc_dir = FSDirectory.from_filesystem(
            path=self.encrypted_dir, filesystem=REAL_FS
        )
        for directory in enc_dir.directories:
            if directory.name == "garbage":
                self.assertEqual(directory.is_encrypted, False)
        # decryption should not fail either
        base.decrypt_directory(
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.decrypted_dir, filesystem=REAL_FS),
        )


class DirectoryComparisonTest(unittest.TestCase):
    """Test directory comparison"""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="backup-test-")
        self.source_dir = os.path.join(self.root, "source")
        self.encrypted_dir = os.path.join(self.root, "encrypted")
        self.decrypted_dir = os.path.join(self.root, "decrypted")
        os.mkdir(self.source_dir)
        os.mkdir(self.encrypted_dir)
        os.mkdir(self.decrypted_dir)

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_compare_same_directory(self):
        """test identical dirs"""
        newdir = "newdir"
        dir1 = FSDirectory(self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory(self.source_dir, filesystem=REAL_FS)
        self.assertIsNone(
            dir1.one_way_diff(dir2), "No difference expected on identical directories"
        )
        os.mkdir(os.path.join(self.source_dir, newdir))
        self.assertIsNone(
            dir1.one_way_diff(dir2), "No difference expected on identical directories"
        )

    def test_commpare_identical_directories_encrypted(self):
        """test identical encrypted dirs"""
        os.mkdir(os.path.join(self.source_dir, "newdir"))
        with open(os.path.join(self.source_dir, "file"), "wb") as tfd:
            tfd.write(b"test")
        with open(os.path.join(self.source_dir, "newdir", "file2"), "wb") as tfd:
            tfd.write(b"test2")
        base.encrypt_directory(
            FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
        )
        dir1 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertIsNone(
            dir1.one_way_diff(dir2),
            "No difference expected on identical encrypted directories",
        )

    def test_extra_source_directory(self):
        """test extra directory in target"""
        new_dir = "new_dir"
        os.mkdir(os.path.join(self.encrypted_dir, new_dir))
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertIsNotNone(
            dir1.one_way_diff(dir2), "Difference expected on different directories"
        )
        # the same again just to make sure we did not change the original
        self.assertIsNotNone(
            dir1.one_way_diff(dir2),
            "Difference expected on different directories on repeated comparison",
        )
        diff = dir1.one_way_diff(dir2)
        self.assertIn(new_dir, diff.dir_names(), "New directory expected in diff")

    def test_extra_nested_directory(self):
        """test extra directory (nested in existing dir) in target"""
        new_dir = "new_dir"
        os.mkdir(os.path.join(self.encrypted_dir, new_dir))
        new_dir2 = "new_dir2"
        os.mkdir(os.path.join(self.encrypted_dir, new_dir, new_dir2))
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertIsNotNone(
            dir1.one_way_diff(dir2), "Difference expected on different directories"
        )
        diff = dir1.one_way_diff(dir2)
        level1_dirs = diff.dir_names()
        self.assertIn(new_dir, level1_dirs, f"{new_dir} expected in level-1 diff")
        self.assertNotIn(
            new_dir2, level1_dirs, f"{new_dir2} not expected in level-1 diff"
        )
        level2_dirs = diff.get_directory(new_dir).dir_names()
        self.assertIn(new_dir2, level2_dirs, f"{new_dir2} expected in level-2 diff")
        self.assertNotIn(
            new_dir, level2_dirs, f"{new_dir} not expected in level-2 diff"
        )

    def test_extra_file(self):
        """test extra file in target"""
        new_file = "new_file"
        with open(
            os.path.join(self.encrypted_dir, new_file), "w", encoding="utf-8"
        ) as tfd:
            tfd.write("test")
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertIsNotNone(
            dir1.one_way_diff(dir2), "Difference expected on different directories"
        )
        diff = dir1.one_way_diff(dir2)
        self.assertIn(new_file, diff.file_names(), f"{new_file} expected in diff")
        self.assertEqual(
            len(diff.directories), 0, "No new directories expected in diff"
        )

    def test_extra_file_in_nested_directory(self):
        """test extra file in nested directory in target"""
        new_dir = "new_dir"
        os.mkdir(os.path.join(self.encrypted_dir, new_dir))
        os.mkdir(os.path.join(self.source_dir, new_dir))
        new_file = "new_file"
        with open(
            os.path.join(self.encrypted_dir, new_dir, new_file), "w", encoding="utf-8"
        ) as tfd:
            tfd.write("test")
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertIsNotNone(
            dir1.one_way_diff(dir2), "Difference expected on different directories"
        )
        diff = dir1.one_way_diff(dir2)
        self.assertEqual(
            len(diff.directories), 1, "Exactly one new directory expected in diff"
        )
        level1_files = diff.file_names()
        self.assertNotIn(
            new_file, level1_files, f"{new_file} not expected in level-1 diff"
        )
        level2_files = diff.get_directory(new_dir).file_names()
        self.assertIn(
            new_file,
            level2_files,
            f"{new_file} expected in level-2 diff. Diff: {diff.dump()}",
        )

    def test_same_content_in_different_dirs(self):
        """test same content (more files) in different dirs"""
        dir1 = "dir1"
        os.mkdir(os.path.join(self.source_dir, dir1))
        os.mkdir(os.path.join(self.encrypted_dir, dir1))
        with open(
            os.path.join(self.source_dir, dir1, "file1"), "w", encoding="utf-8"
        ) as tfd:
            tfd.write("test")
        with open(
            os.path.join(self.encrypted_dir, dir1, "file1"), "w", encoding="utf-8"
        ) as tfd:
            tfd.write("test")
        with open(
            os.path.join(self.source_dir, "rootfile1"), "w", encoding="utf-8"
        ) as tfd:
            tfd.write("test")
        with open(
            os.path.join(self.encrypted_dir, "rootfile1"), "w", encoding="utf-8"
        ) as tfd:
            tfd.write("test")
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertIsNone(
            dir1.one_way_diff(dir2), "No difference expected on identical directories"
        )

    def test_two_extra_empty_directories(self):
        """test two extra empty directories in target"""
        dir1 = "dir1"
        dir2 = "dir2"
        os.mkdir(os.path.join(self.encrypted_dir, dir1))
        os.mkdir(os.path.join(self.encrypted_dir, dir2))
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertIsNotNone(
            dir1.one_way_diff(dir2), "Difference expected on different directories"
        )
        self.assertEqual(
            len(dir1.one_way_diff(dir2).directories),
            2,
            "Two new directories expected in diff",
        )

    def test_encrypt_and_compare(self):
        """encrypts a directory and runs a diff on it"""
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        base.encrypt_directory(
            FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
        )
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        diff = dir1.one_way_diff(dir2)
        self.assertIsNone(diff, "No difference expected on identical directories")

    def test_sub_operator(self):
        """test sub operator"""
        os.mkdir(os.path.join(self.encrypted_dir, "dir1"))
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        diff = dir2 - dir1
        self.assertIsNotNone(diff, "Difference expected on different directories")
        diff2 = dir1.one_way_diff(dir2)
        self.assertIsNotNone(diff2, "Difference expected on different directories")
        self.assertIn("dir1", diff.dir_names(), "dir1 expected in diff")
        self.assertIn("dir1", diff2.dir_names(), "dir1 expected in diff2")

    def test_eq_operator(self):
        """test eq operator"""
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertEqual(dir1, dir2, "Directories should be equal")
        # extra dir in target
        os.mkdir(os.path.join(self.encrypted_dir, "newdir"))
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertNotEqual(dir1, dir2, "Directories should not be equal")
        os.rmdir(os.path.join(self.encrypted_dir, "newdir"))
        # extra dir in source
        os.mkdir(os.path.join(self.source_dir, "newdir"))
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertNotEqual(dir1, dir2, "Directories should not be equal")
        os.rmdir(os.path.join(self.source_dir, "newdir"))
        # extra file in target
        with open(
            os.path.join(self.encrypted_dir, "newfile"), "w", encoding="utf-8"
        ) as tfd:
            tfd.write("test")
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertNotEqual(dir1, dir2, "Directories should not be equal")
        os.remove(os.path.join(self.encrypted_dir, "newfile"))
        # extra file in source
        with open(
            os.path.join(self.source_dir, "newfile"), "w", encoding="utf-8"
        ) as tfd:
            tfd.write("test")
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        dir2 = FSDirectory.from_filesystem(path=self.encrypted_dir, filesystem=REAL_FS)
        self.assertNotEqual(dir1, dir2, "Directories should not be equal")
        os.remove(os.path.join(self.source_dir, "newfile"))


class FSDirectoryTest(unittest.TestCase):
    """Tests for FSDirectory class"""

    def test_add_str_instead_of_dir(self):
        """test adding string instead of FSDirectory object"""
        dir1 = FSDirectory(path="root", filesystem=REAL_FS)
        with self.assertRaises(TypeError):
            dir1.add_directory("dir1")

    def test_duplicit_dir_add(self):
        """test adding directory with same name as existing one"""
        dir1 = FSDirectory(path="root", filesystem=REAL_FS)
        dir1.add_directory(FSDirectory("dir1", filesystem=REAL_FS))
        with self.assertRaises(
            ValueError, msg="Adding already existing name should raise ValueError"
        ):
            dir1.add_directory(FSDirectory("dir1", filesystem=REAL_FS))

    def test_add_str_instead_of_file(self):
        """test adding string instead of FSFile object"""
        dir1 = FSDirectory(path="root", filesystem=REAL_FS)
        with self.assertRaises(TypeError):
            dir1.add_file("file1")

    def test_add_duplicit_file(self):
        """test adding file with same name as existing one"""
        dir1 = FSDirectory(path="root", filesystem=REAL_FS)
        dir1.add_file(FSFile("file1", filesystem=REAL_FS))
        with self.assertRaises(
            ValueError, msg="Adding already existing name should raise ValueError"
        ):
            dir1.add_file(FSFile("file1", filesystem=REAL_FS))

    def test_add_file_with_same_name_as_dir(self):
        """test adding file with same name as existing directory"""
        dir1 = FSDirectory(path="root", filesystem=REAL_FS)
        dir1.add_directory(FSDirectory("dir1", filesystem=REAL_FS))
        with self.assertRaises(
            ValueError, msg="Adding already existing name should raise ValueError"
        ):
            dir1.add_file(FSFile("dir1", filesystem=REAL_FS))

    def test_add_dir_with_same_name_as_file(self):
        """test adding directory with same name as existing file"""
        dir1 = FSDirectory(path="root", filesystem=REAL_FS)
        dir1.add_file(FSFile("file1", filesystem=REAL_FS))
        with self.assertRaises(
            ValueError, msg="Adding already existing name should raise ValueError"
        ):
            dir1.add_directory(FSDirectory("file1", filesystem=REAL_FS))

    def test_different_fs_raises_error(self):
        """test adding directory with different filesystem raises an error"""
        dir1 = FSDirectory(path="root", filesystem=REAL_FS)
        dir2 = FSDirectory(path="root", filesystem=Mock())
        with self.assertRaises(
            ValueError,
            msg="Adding directory with different filesystem should raise ValueError",
        ):
            dir1.add_directory(dir2)

    def test_diffferent_file_fs_raises_error(self):
        """test adding file with different filesystem raises an error"""
        dir1 = FSDirectory(path="root", filesystem=REAL_FS)
        file1 = FSFile(name="file1", filesystem=Mock())
        with self.assertRaises(
            ValueError,
            msg="Adding file with different filesystem should raise ValueError",
        ):
            dir1.add_file(file1)

    def test_deepcopy_keeps_filesystem(self):
        """test that deepcopy keeps the filesystem"""
        dir1 = FSDirectory(path="root", filesystem=REAL_FS)
        dir2 = deepcopy(dir1)
        self.assertEqual(dir1.filesystem, dir2.filesystem)


class FSDirectoryFilesystemParsingTest(unittest.TestCase):
    """
    Tests for file system parsing function of FSDirectory class
    """

    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="backup-test-")
        self.source_dir = os.path.join(self.root, "source")
        self.encrypted_dir = os.path.join(self.root, "encrypted")
        self.decrypted_dir = os.path.join(self.root, "decrypted")
        os.mkdir(self.source_dir)
        os.mkdir(self.encrypted_dir)
        os.mkdir(self.decrypted_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.root)

    def test_empty_directory(self):
        """test empty directory"""
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        self.assertEqual(dir1.name, os.path.basename(self.source_dir))
        self.assertEqual(dir1.dir_names(), set([]))
        self.assertEqual(dir1.file_names(), set([]))

    def test_directory_with_one_file(self):
        """test directory with one file"""
        with open(os.path.join(self.source_dir, "file1"), "wb") as tfd:
            tfd.write(b"test")
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        self.assertEqual(dir1.name, os.path.basename(self.source_dir))
        self.assertEqual(dir1.dir_names(), set([]))
        self.assertEqual(dir1.file_names(), set(["file1"]))

    def test_directory_with_one_directory(self):
        """test directory with one directory"""
        os.mkdir(os.path.join(self.source_dir, "dir1"))
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        self.assertEqual(dir1.name, os.path.basename(self.source_dir))
        self.assertEqual(dir1.dir_names(), set(["dir1"]))
        self.assertEqual(dir1.file_names(), set([]))

    def test_directory_with_one_file_and_one_directory(self):
        """test directory with one file and one directory"""
        os.mkdir(os.path.join(self.source_dir, "dir1"))
        with open(os.path.join(self.source_dir, "file1"), "wb") as tfd:
            tfd.write(b"test")
        dir1 = FSDirectory.from_filesystem(path=self.source_dir, filesystem=REAL_FS)
        self.assertEqual(dir1.name, os.path.basename(self.source_dir))
        self.assertEqual(dir1.dir_names(), set(["dir1"]))
        self.assertEqual(dir1.file_names(), set(["file1"]))

    def test_parse_plaintext_tree(self):
        """tests parsing functionality of to-be-encrypted trees"""
        tree = {
            "dir1": {"dir-1-1": {}, "dir-1-2": {"file-1-2": "test"}, "file1": "test"},
            "dir2": {"file2": "test2"},
            "file3": "test3",
        }
        create_fs_tree_from_dict(self.source_dir, tree)
        parsed_dir = FSDirectory.from_filesystem(
            path=self.source_dir, filesystem=REAL_FS
        )
        self.assertEqual(parsed_dir.dir_names(), set(["dir1", "dir2"]))
        self.assertEqual(parsed_dir.file_names(), set(["file3"]))
        dir1_1 = parsed_dir.get_directory("dir1")
        self.assertEqual(dir1_1.dir_names(), set(["dir-1-1", "dir-1-2"]))
        self.assertEqual(dir1_1.file_names(), set(["file1"]))
        dir1_2 = dir1_1.get_directory("dir-1-2")
        self.assertEqual(dir1_2.dir_names(), set([]))
        self.assertEqual(dir1_2.file_names(), set(["file-1-2"]))
        dir2 = parsed_dir.get_directory("dir2")
        self.assertEqual(dir2.dir_names(), set([]))
        self.assertEqual(dir2.file_names(), set(["file2"]))

    def test_parse_plaintext_tree_nonrecursive(self):
        """
        tests parsing functionality of to-be-encrypted trees
        non-recurisve
        """
        tree = {
            "dir1": {"dir-1-1": {}, "dir-1-2": {"file-1-2": "test"}, "file1": "test"},
            "dir2": {"file2": "test2"},
            "file3": "test3",
        }
        create_fs_tree_from_dict(self.source_dir, tree)
        parsed_dir = FSDirectory.from_filesystem(
            path=self.source_dir, filesystem=REAL_FS, recursive=False
        )
        # first level has all items
        self.assertEqual(parsed_dir.dir_names(), set(["dir1", "dir2"]))
        self.assertEqual(parsed_dir.file_names(), set(["file3"]))
        # those items must be empty though (no recursion requirement)
        dir1_1 = parsed_dir.get_directory("dir1")
        self.assertEqual(dir1_1.dir_names(), set([]))
        self.assertEqual(dir1_1.file_names(), set([]))
        dir1_2 = parsed_dir.get_directory("dir2")
        self.assertEqual(dir1_2.dir_names(), set([]))
        self.assertEqual(dir1_2.file_names(), set([]))

    def test_parse_encrypted_tree(self):
        """tests parsing functionality of encrypted trees"""
        tree = {
            "dir1": {"dir-1-1": {}, "dir-1-2": {"file-1-2": "test"}, "file1": "test"},
            "dir2": {"file2": "test2"},
            "file3": "test3",
        }
        create_fs_tree_from_dict(self.source_dir, tree)
        base.encrypt_directory(
            FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
        )
        parsed_dir = FSDirectory.from_filesystem(
            path=self.encrypted_dir, filesystem=REAL_FS
        )
        self.assertFalse(parsed_dir.is_encrypted)  # target dir is plaintext normally
        self.assertEqual(parsed_dir.dir_names(), set(["dir1", "dir2"]))
        self.assertEqual(parsed_dir.file_names(), set(["file3"]))
        dir1_1 = parsed_dir.get_directory("dir1")
        self.assertTrue(dir1_1.is_encrypted)
        self.assertNotEqual(dir1_1.name, dir1_1.decrypted_name)
        self.assertEqual(dir1_1.dir_names(), set(["dir-1-1", "dir-1-2"]))
        self.assertEqual(dir1_1.file_names(), set(["file1"]))
        dir1_2 = dir1_1.get_directory("dir-1-2")
        self.assertNotEqual(dir1_2.name, dir1_2.decrypted_name)
        self.assertTrue(dir1_2.is_encrypted)
        self.assertEqual(dir1_2.dir_names(), set([]))
        self.assertEqual(dir1_2.file_names(), set(["file-1-2"]))
        dir2 = parsed_dir.get_directory("dir2")
        self.assertNotEqual(dir2.name, dir2.decrypted_name)
        self.assertTrue(dir2.is_encrypted)
        self.assertEqual(dir2.dir_names(), set([]))
        self.assertEqual(dir2.file_names(), set(["file2"]))

    def test_parse_encrypted_tree_nonrecursive(self):
        """
        tests parsing functionality of encrypted trees
        non-recursive
        """
        tree = {
            "dir1": {"dir-1-1": {}, "dir-1-2": {"file-1-2": "test"}, "file1": "test"},
            "dir2": {"file2": "test2"},
            "file3": "test3",
        }
        create_fs_tree_from_dict(self.source_dir, tree)
        base.encrypt_directory(
            FSDirectory.from_filesystem(self.source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(self.encrypted_dir, filesystem=REAL_FS),
        )
        parsed_dir = FSDirectory.from_filesystem(
            path=self.encrypted_dir, filesystem=REAL_FS, recursive=False
        )
        self.assertFalse(parsed_dir.is_encrypted)  # target dir is plaintext normally
        self.assertEqual(parsed_dir.dir_names(), set(["dir1", "dir2"]))
        self.assertEqual(parsed_dir.file_names(), set(["file3"]))
        dir1_1 = parsed_dir.get_directory("dir1")
        self.assertTrue(dir1_1.is_encrypted)
        self.assertNotEqual(dir1_1.name, dir1_1.decrypted_name)
        self.assertEqual(dir1_1.dir_names(), set([]))
        self.assertEqual(dir1_1.file_names(), set([]))
        dir1_2 = parsed_dir.get_directory("dir2")
        self.assertTrue(dir1_2.is_encrypted)
        self.assertNotEqual(dir1_2.name, dir1_2.decrypted_name)
        self.assertEqual(dir1_2.dir_names(), set([]))
        self.assertEqual(dir1_2.file_names(), set([]))


class StatusReporterTest(unittest.TestCase):
    """Test status reporter"""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="backup-test-")

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_encryption_status_reporter(self):
        """test encryption status reporter"""
        source_dir = os.path.join(self.root, "source")
        encrypted_dir = os.path.join(self.root, "encrypted")
        os.mkdir(source_dir)
        os.mkdir(encrypted_dir)
        create_fs_tree(source_dir)
        reporter = base.StatusReporter()
        base.STATUS_REPORTER = reporter
        base.encrypt_directory(
            FSDirectory.from_filesystem(source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(encrypted_dir, filesystem=REAL_FS),
        )
        encrypted_count = reporter.files_processed
        self.assertGreater(encrypted_count, 0, "Encrypted files were not reported")
        base.encrypt_directory(
            FSDirectory.from_filesystem(source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(encrypted_dir, filesystem=REAL_FS),
        )
        self.assertEqual(
            reporter.files_processed,  # all skipped will be processed again
            reporter.files_skipped,
            "Skipped and processed counts must match on second run.",
        )

    def test_decryption_status_reporter(self):
        """test decryption status reporter"""
        source_dir = os.path.join(self.root, "source")
        encrypted_dir = os.path.join(self.root, "encrypted")
        decrypted_dir = os.path.join(self.root, "decrypted")
        os.mkdir(source_dir)
        os.mkdir(encrypted_dir)
        os.mkdir(decrypted_dir)
        create_fs_tree(source_dir)
        base.encrypt_directory(
            FSDirectory.from_filesystem(source_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(encrypted_dir, filesystem=REAL_FS),
        )
        reporter = base.StatusReporter()
        base.STATUS_REPORTER = reporter
        base.decrypt_directory(
            FSDirectory.from_filesystem(encrypted_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(decrypted_dir, filesystem=REAL_FS),
        )
        decrypted_count = reporter.files_processed
        self.assertGreater(decrypted_count, 0, "Decrypted files were not reported")
        base.decrypt_directory(
            FSDirectory.from_filesystem(encrypted_dir, filesystem=REAL_FS),
            FSDirectory.from_filesystem(decrypted_dir, filesystem=REAL_FS),
        )
        self.assertEqual(
            reporter.files_processed,  # all skipped will be processed again
            reporter.files_skipped,
            "Skipped and processed counts must match on second run.",
        )


class RealFilesystemPathLimitTest(unittest.TestCase):
    """Tests for filesystem operations above path length limits"""

    # pylint: disable=invalid-name
    #         (fd and fs are ok)
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="backup-test-")
        self.fs = RealFilesystem()

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_max_path_limits(self):
        """test operations with paths longer than filesystem limits (typically 4096 bytes)"""
        oversize_path_length = 4096 + 1024
        max_path_root = self.root
        fs = self.fs
        _iter = 0
        while len(max_path_root) < oversize_path_length:
            max_path_root = os.path.join(max_path_root, f"{_iter:03d}-dir")
            _iter += 1
        fs.makedirs(max_path_root)
        self.assertTrue(
            fs.exists(max_path_root), "root does not exist when it should already"
        )
        fs.mkdir(os.path.join(max_path_root, "dir1"))
        testfile = os.path.join(max_path_root, "dir1", "file1")
        with fs.open(testfile, "wb") as tfd:
            tfd.write(b"test")
        with fs.open(testfile, "rb") as tfd:
            self.assertEqual(tfd.read(), b"test")
        fs.unlink(testfile)
        self.assertFalse(fs.exists(testfile))
        fs.chdir(max_path_root)
        self.assertEqual(fs.getcwd(), max_path_root)
        with fs.cwd_cm(max_path_root):
            fs.mkdir("dir2")
        self.assertTrue(
            fs.exists(os.path.join(max_path_root, "dir2")),
            "directory not created in proper place while using cwd context manager",
        )
        fs.rmdir(os.path.join(max_path_root, "dir2"))
        self.assertFalse(
            fs.exists(os.path.join(max_path_root, "dir2")),
        )
        walk_data = list(fs.walk(self.root))
        self.assertIn(
            "dir1",
            walk_data[-2][1],  # -1 is dir1 itself, -2 is its parent
            "walk probably did not finish at the end of the path",
        )
        fs.rmtree(max_path_root)
        self.assertFalse(fs.exists(max_path_root))


class VirtualFilesystemPathLimitTest(RealFilesystemPathLimitTest):
    """Tests for filesystem operations above path length limits"""

    def setUp(self):
        self.fs = VirtualFilesystem()
        test_dir = "/" + "".join(random.choices(string.ascii_lowercase, k=10))
        self.root = test_dir
        self.fs.mkdir(test_dir)

    def tearDown(self):
        self.fs.rmtree(self.root)


class VirtualFilesystemTest(unittest.TestCase):
    """Tests for virtual filesystem"""

    # pylint: disable=invalid-name
    #         (fd and fs are ok)
    def test_vfs_basics(self):
        """test isdir"""
        vfs = VirtualFilesystem()
        # empty test
        self.assertFalse(vfs.is_dir("dir1"))
        vfs.mkdir("dir1")
        self.assertTrue(vfs.is_dir("dir1"))
        self.assertFalse(vfs.is_dir("dir2"))
        with self.assertRaises(IOError):
            vfs.mkdir("dir1")
        with self.assertRaises(IOError):
            vfs.mkdir("/a/b")
        vfs.makedirs("/a/b")
        self.assertTrue(vfs.is_dir("/a/b"))
        vfs.chdir("/a/b")
        vfs.mkdir("c")
        self.assertTrue(vfs.is_dir("c"))
        self.assertTrue(vfs.is_dir("/a/b/c"))
        data = b"test"
        with vfs.open("/a/b/file", "wb") as fd:
            fd.write(data)
        self.assertTrue(vfs.exists("/a/b/file"))
        with vfs.open("/a/b/file", "rb") as fd:
            self.assertEqual(fd.read(), data)
        with self.assertRaises(IOError):
            vfs.open("/a/b/nonexistent", "rb")
        with self.assertRaises(NotImplementedError):
            # testing requirement that mode must be binary
            vfs.open("/file", "w")
        vfs.chdir("/")
        vfs.makedirs("x/y")
        self.assertTrue(vfs.exists("/x/y"))
        #        with self.assertRaises(IOError):
        #            vfs.mkdir("/")
        with self.assertRaises(IOError):
            vfs.makedirs("/")
        vfs.makedirs("/", exist_ok=True)
        vfs.mkdir("/abc")  # no slash at the end
        with self.assertRaises(IOError):
            vfs.mkdir("/abc/")  # slash at the end
        vfs.rmdir("/abc")  # without a slash
        vfs.mkdir("/abc/")
        with self.assertRaises(IOError):
            vfs.mkdir("/abc")
        vfs.rmdir("/abc/")  # again, with a slash
        vfs.mkdir("///abcd")
        self.assertTrue(vfs.exists("/abcd"))
        self.assertTrue(vfs.exists("///abcd"))
        vfs.chdir("/abcd")
        vfs.mkdir("e/")
        self.assertTrue(vfs.exists("/abcd/e"))
        vfs.mkdir("///xy//")
        self.assertTrue(vfs.exists("/xy"))
        vfs.makedirs("///ef//gh//")
        self.assertTrue(vfs.exists("/ef/gh"))
        with self.assertRaises(IOError):
            vfs.mkdir("")
        with vfs.open("/not-a-directory", "wb") as fd:
            fd.write(b"test")
        with self.assertRaises(IOError):
            vfs.rmdir("/not-a-directory")

    def test_vfs_walk(self):
        """Tests vfs.walk for results matching os.walk structure"""
        vfs = VirtualFilesystem()
        vfs.makedirs("/a/b/c")
        with vfs.open("/a/b/file", "wb") as fd:
            fd.write(b"test file in /a/b dir")
        walker = vfs.walk("/")
        expected = [
            ("/", ["a"], []),
            ("/a", ["b"], []),
            ("/a/b", ["c"], ["file"]),
            ("/a/b/c", [], []),
        ]
        actual = list(walker)
        self.assertEqual(actual, expected)
        self.assertEqual(list(vfs.walk("/a/b/file")), [("/a/b/file", [], [])])

    def test_relative_paths(self):
        """Tests basic operations with relative paths"""
        vfs = VirtualFilesystem()
        vfs.makedirs("/a/b/c")
        vfs.chdir("/a")
        vfs.chdir("b")
        vfs.mkdir("c/d")
        self.assertTrue(vfs.exists("/a/b/c/d"))


class VirtualFileEncryptorTest(FileEncryptorTest):
    """Test file encryption"""

    def setUp(self):
        self.test_dir = "/" + "".join(random.choices(string.ascii_lowercase, k=10))
        VIRT_FS.mkdir(self.test_dir)
        self.test_file = self.get_temp_file()
        self.test_data = b"test" * 1024 * 1024
        with VIRT_FS.open(self.test_file, "wb") as tfd:
            tfd.write(self.test_data)
        self.filesystem = VIRT_FS

    def get_temp_file(self, prefix=""):
        """Get a temporary file path"""
        # pylint: disable=invalid-name
        temp_file = prefix + "".join(random.choices(string.ascii_lowercase, k=10))
        temp_file_path = os.path.join(self.test_dir, temp_file)
        with VIRT_FS.open(temp_file_path, "wb") as tfd:
            tfd.write(b"")
        return temp_file_path

    def tearDown(self):
        VIRT_FS.rmtree(self.test_dir)


@unittest.skipIf(
    "S3_BUCKET" not in os.environ or not "AWS_PROFILE" in os.environ,
    "S3_BUCKET and AWS_PROFILE environment variables must be set to run "
    "S3FileSystemTest",
)
class S3FileSystemTest(unittest.TestCase):
    """Test basic filesystem operations on S3 filesystem"""

    # pylint: disable=import-outside-toplevel
    def __init__(self, *args, **kwargs):
        from awsfilesystem import AWS_MAX_OBJECT_NAME_LENGTH

        super().__init__(*args, **kwargs)
        self.testdir = (
            "/"
            + "backup-ci-test-"
            + "".join(random.choices(string.ascii_lowercase, k=10))
        )
        self.pathlimit = AWS_MAX_OBJECT_NAME_LENGTH

    def setUp(self):
        from awsfilesystem import AWSFilesystem

        # this cannot be in init as it would be called by unittest even
        # if the class is skipped
        self.vfs = AWSFilesystem(
            os.environ["S3_BUCKET"], profile=os.environ["AWS_PROFILE"]
        )

    def tearDown(self):
        try:
            self.vfs.rmtree(self.testdir)
        except Exception as ex:  # pylint: disable=broad-except
            log.info("Failed to remove test directory (non-fatal error): %s", ex)

    def test_s3_write_proxy(self):
        """Tests that write operations are done through write proxy"""
        # pylint: disable=invalid-name # pylint does not like "fd" and we do ;)
        vfs = self.vfs
        import awsfilesystem  # pylint: disable=import-outside-toplevel

        # assert the actual call
        with patch.object(awsfilesystem.S3WriteProxy, "__enter__") as mock_enter:
            with vfs.open(os.path.join(self.testdir, "fileX"), "wb") as fd:
                fd.write(b"test")
        mock_enter.assert_called_once()

        # test real-life behavior
        with vfs.open(os.path.join(self.testdir, "file1"), "wb") as fd:
            fd.write(b"test")
            # file should not exist at this moment
            self.assertFalse(vfs.exists(os.path.join(self.testdir, "file1")))
        self.assertTrue(vfs.exists(os.path.join(self.testdir, "file1")))
        # after closing, it should have been uploaded, contents should match
        with vfs.open(os.path.join(self.testdir, "file1"), "rb") as fd:
            self.assertEqual(fd.read(), b"test")
        # overwrite with new data
        with vfs.open(os.path.join(self.testdir, "file1"), "wb") as fd:
            fd.write(b"test2")
        with vfs.open(os.path.join(self.testdir, "file1"), "rb") as fd:
            self.assertEqual(fd.read(), b"test2")

    def test_s3_basics(self):
        """test basic s3 filesystem operations"""
        vfs = self.vfs
        # setup of safe space, not done in init just to delay
        # failures in case of misconfiguration
        vfs.makedirs(self.testdir)

        # in s3fs dirs are not made if they do not contain any files.
        # It's tricky as writing to a dir that does not exist fails,
        # but creating it does not cause is_dir or exist() to return True
        vfs.mkdir(os.path.join(self.testdir, "dir1"))
        # basic file/dir exist checks
        with vfs.open(os.path.join(self.testdir, "dir1", "file1"), "wb") as tfd:
            tfd.write(b"test")
        self.assertTrue(vfs.exists(os.path.join(self.testdir, "dir1")))
        self.assertTrue(vfs.exists(os.path.join(self.testdir, "dir1", "file1")))
        self.assertTrue(vfs.is_dir(os.path.join(self.testdir, "dir1")))
        self.assertFalse(vfs.is_dir(os.path.join(self.testdir, "dir1", "file1")))
        # non-existent directories still return True
        self.assertTrue(vfs.is_dir(os.path.join(self.testdir, "dir1", "nonexistent")))
        with vfs.open(os.path.join(self.testdir, "dir1", "file1"), "rb") as tfd:
            self.assertEqual(tfd.read(), b"test")
        vfs.chdir(self.testdir)
        # get_size check
        self.assertEqual(vfs.get_size("dir1/file1"), 4)
        # relative paths check
        self.assertTrue(vfs.exists("dir1"))
        self.assertTrue(vfs.exists("dir1/file1"))
        self.assertTrue(vfs.is_dir("dir1"))
        vfs.chdir(self.testdir)
        # cm check
        with vfs.cwd_cm(os.path.join(self.testdir, "dir1")):
            self.assertTrue(vfs.exists("file1"))
        self.assertEqual(vfs.getcwd(), self.testdir)
        # unlink check
        with vfs.open(os.path.join(self.testdir, "dir1", "file2"), "wb") as tfd:
            tfd.write(b"test2")
        self.assertTrue(vfs.exists(os.path.join(self.testdir, "dir1", "file2")))
        vfs.unlink(os.path.join(self.testdir, "dir1", "file2"))
        self.assertFalse(vfs.exists(os.path.join(self.testdir, "dir1", "file2")))
        # os.walk check
        walk = list(vfs.walk(self.testdir))
        expected = [
            (self.testdir, ["dir1"], []),
            (f"{self.testdir}/dir1", [], ["file1"]),
        ]
        self.assertEqual(walk, expected)
        # relative paths walk
        with vfs.cwd_cm(self.testdir):
            walk = list(vfs.walk("."))
            expected = [(".", ["dir1"], []), ("./dir1", [], ["file1"])]
            self.assertEqual(walk, expected)
        # s3 path tests
        with vfs.cwd_cm(self.testdir):
            self.assertEqual(vfs.abs_path("."), self.testdir)
            self.assertEqual(vfs.abs_path("dir1"), f"{self.testdir}/dir1")
            self.assertEqual(
                vfs.abs_s3_path("dir1"), f"{vfs.bucket}{self.testdir}/dir1"
            )
        with self.assertRaises(OSError):
            vfs.rmdir(os.path.join(self.testdir, "dir1"))
        # extra dir with file
        vfs.mkdir(os.path.join(self.testdir, "dir2"))
        # need a file in a dir so that s3fs actually creates the dir
        with vfs.open(os.path.join(self.testdir, "dir2", "file1"), "wb") as tfd:
            tfd.write(b"test")
        # rmtree test
        vfs.rmtree(os.path.join(self.testdir, "dir1"))
        self.assertFalse(vfs.exists(os.path.join(self.testdir, "dir1")))
        # safety check :)
        self.assertTrue(vfs.exists(os.path.join(self.testdir, "dir2")))
        # over limit mkdir
        dir_str = self.testdir
        while len(dir_str) < self.pathlimit:
            dir_str = os.path.join(dir_str, "extralongdirname")
        max_dir_str = dir_str[: self.pathlimit - 1]
        vfs.makedirs(os.path.join(self.testdir, max_dir_str))  # must succeed
        # dirs over path limit
        with self.assertRaises(OSError):
            vfs.makedirs(os.path.join(self.testdir, dir_str))
        # file open over path limit
        with self.assertRaises(OSError):
            # with the dir name at the limit anything opened inside
            # must cause an error
            vfs.open(os.path.join(self.testdir, max_dir_str, "file1"), "wb")


class TestCommandLineUtility(unittest.TestCase):
    """Test command line utility"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.root = tempfile.mkdtemp(prefix="backup-test-")
        self.source_dir = os.path.join(self.root, "source")
        self.encrypted_dir = os.path.join(self.root, "encrypted")
        self.decrypted_dir = os.path.join(self.root, "decrypted")
        self.command = os.path.join(os.path.dirname(__file__), "backup.py")
        self.base_params = [
            "--scrypt-n",
            "16384",
            "--password",
            "x",
        ]

    def setUp(self):
        os.mkdir(self.source_dir)
        os.mkdir(self.encrypted_dir)
        os.mkdir(self.decrypted_dir)
        self.tree_init()

    def tearDown(self):
        shutil.rmtree(self.root)

    def tree_init(self):
        """Initialize test tree"""
        tree = {
            "dir1": {"dir-1-1": {}, "dir-1-2": {"file-1-2": "test"}, "file1": "test"},
            "dir2": {"file2": "test2"},
            "file3": "test3",
        }
        create_fs_tree_from_dict(self.source_dir, tree)

    def exec(
        self, args_list, input=None, timeout=60
    ):  # pylint: disable=redefined-builtin
        """Execute command line utility"""
        return subprocess.run(
            [self.command] + args_list,
            check=False,
            capture_output=True,
            timeout=timeout,
            input=input,
        )

    def dirs_equal(self, first, second):
        """Compares two directories that are expected to be equal."""
        files_first = sorted(
            [_.replace(first, "") for _ in glob.glob(first + "/**", recursive=True)]
        )
        second_files = sorted(
            [_.replace(second, "") for _ in glob.glob(second + "/**", recursive=True)]
        )
        return files_first == second_files

    def test_encryption_decryption(self):
        """test basic encryption and decryption worklfow"""

        # encrypt first
        result = self.exec(
            self.base_params
            + [
                "--encrypt",
                self.source_dir,
                self.encrypted_dir,
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)

        # decrypt
        result = self.exec(
            self.base_params
            + [
                "--decrypt",
                self.encrypted_dir,
                self.decrypted_dir,
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)
        # make sure files are the same after decryption (names + structure only)
        self.assertTrue(self.dirs_equal(self.source_dir, self.decrypted_dir))

    def test_new_file(self):
        """test new file creation"""
        result = self.exec(
            self.base_params
            + [
                "--encrypt",
                self.source_dir,
                self.encrypted_dir,
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)
        # create a new file in source dir
        with open(os.path.join(self.source_dir, "newfile"), "wb") as tfd:
            tfd.write(b"test")
        # encrypt again
        result = self.exec(
            self.base_params
            + [
                "--encrypt",
                self.source_dir,
                self.encrypted_dir,
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)
        # decrypt
        result = self.exec(
            self.base_params
            + [
                "--decrypt",
                self.encrypted_dir,
                self.decrypted_dir,
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)
        # make sure files are the same after decryption (names + structure only)
        self.assertTrue(self.dirs_equal(self.source_dir, self.decrypted_dir))

    def test_skip_unencrypted_file(self):
        """test skipping unencrypted file"""
        result = self.exec(
            self.base_params
            + [
                "--encrypt",
                self.source_dir,
                self.encrypted_dir,
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)
        # create a plain unecrypted file in encrypted_dir
        with open(os.path.join(self.encrypted_dir, "newfile"), "wb") as tfd:
            tfd.write(b"test")
        # decrypt the encrypted dir
        result = self.exec(
            self.base_params
            + [
                "--decrypt",
                self.encrypted_dir,
                self.decrypted_dir,
            ],
        )
        # source and decrypted dirs should be the same
        # the new file should have been ignored
        self.assertTrue(self.dirs_equal(self.source_dir, self.decrypted_dir))

    def test_slash_no_problem(self):
        """test that trailing slash does not cause problems"""
        result = self.exec(
            self.base_params
            + [
                "--encrypt",
                self.source_dir + "/",
                self.encrypted_dir + "/",
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)
        # decrypt
        result = self.exec(
            self.base_params
            + [
                "--decrypt",
                self.encrypted_dir + "/",
                self.decrypted_dir + "/",
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)
        # make sure files are the same after decryption (names + structure only)
        self.assertTrue(self.dirs_equal(self.source_dir, self.decrypted_dir))

    def test_listing(self):
        """test listing of source and encrypted directory"""
        result = self.exec(
            self.base_params
            + [
                "--encrypt",
                self.source_dir,
                self.encrypted_dir,
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)
        # list
        result = self.exec(
            self.base_params
            + [
                "--list",
                self.source_dir,
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)
        # make sure listings are equal
        source_files = sorted(glob.glob(self.source_dir + "/**", recursive=True))[1:]
        listed_files = sorted(result.stdout.decode("utf-8").splitlines())
        self.assertEqual(source_files, listed_files)
        # list encrypted
        result = self.exec(
            self.base_params
            + [
                "--list",
                self.encrypted_dir,
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)
        # make sure listings are equal
        listed_enc_files = [
            # replace paths in output to allow 1-1 matching
            _.replace(self.encrypted_dir, self.source_dir)
            for _ in sorted(result.stdout.decode("utf-8").splitlines())
        ]
        self.assertEqual(source_files, listed_enc_files)

        # verbose listing should show encrypted files
        result = self.exec(
            self.base_params
            + [
                "--verbose",
                "--list",
                self.encrypted_dir,
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)
        # for each line of encrypted input it should be split by '->'
        # and left part should be plaintext file and right part encrypted version
        for line in result.stdout.decode("utf-8").splitlines():
            parts = line.split("->")
            self.assertEqual(len(parts), 2)
            self.assertFalse(parts[0].strip() == parts[1].strip())

        # verbose listing of source dir should show plaintext files
        # on both sides
        result = self.exec(
            self.base_params
            + [
                "--verbose",
                "--list",
                self.source_dir,
            ],
        )
        log.debug(result.stdout)
        log.debug(result.stderr)
        self.assertEqual(result.returncode, 0)
        # for each line of encrypted input it should be split by '->'
        # and left line should be plaintext file and right part equal to left
        for line in result.stdout.decode("utf-8").splitlines():
            parts = line.strip().split("->")
            self.assertEqual(len(parts), 2)
            self.assertTrue(parts[0].strip() == parts[1].strip())

    def test_nonexistent_dirs(self):
        """Test encrypt, decrypt and list on non-existent directories"""
        non_existent_dir = os.path.join(self.root, "non-existent")
        # non-existent source dir should fail
        result = self.exec(
            self.base_params
            + [
                "--encrypt",
                non_existent_dir,
                self.encrypted_dir,
            ],
        )
        self.assertNotEqual(result.returncode, 0)
        # non-existent target dir should succeed
        result = self.exec(
            self.base_params
            + [
                "--encrypt",
                self.source_dir,
                non_existent_dir,
            ],
        )
        self.assertTrue(os.path.exists(non_existent_dir))
        self.assertEqual(result.returncode, 0)
        shutil.rmtree(non_existent_dir)

        # decryption
        result = self.exec(
            self.base_params
            + [
                "--decrypt",
                non_existent_dir,
                self.decrypted_dir,
            ],
        )
        self.assertNotEqual(result.returncode, 0)
        # non-existent target should be created
        result = self.exec(
            self.base_params
            + [
                "--decrypt",
                self.encrypted_dir,
                non_existent_dir,
            ],
        )
        self.assertTrue(os.path.exists(non_existent_dir))
        self.assertEqual(result.returncode, 0)
        shutil.rmtree(non_existent_dir)

        # listing
        result = self.exec(
            self.base_params
            + [
                "--list",
                non_existent_dir,
            ],
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
