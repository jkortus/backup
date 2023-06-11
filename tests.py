""" Unit tests for backup tool """
import os
import unittest
import tempfile
import base64
import shutil
import logging
import cryptography.exceptions
import backup
from backup import EncryptionKey, FSDirectory, FSFile

backup.log.setLevel(backup.logging.WARNING)

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)


# pylint: disable=logging-fstring-interpolation


class EncryptionKeyTest(unittest.TestCase):
    """Test encryption key class"""

    def test_new_key(self):
        """Test creation of new key"""
        password = "test"
        key = EncryptionKey(password=password)
        self.assertEqual(len(key.key), 32)
        self.assertEqual(len(key.salt), backup.SALT_SIZE_BYTES)

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
        self.password = "test"

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
        key = EncryptionKey(password=self.password)
        # encrypt buffered
        encryptor = backup.FileEncryptor(path=self.test_file, key=key)
        encrypted_data = b""
        buffer_size = 1024 * 10
        while True:
            new_data = encryptor.read(buffer_size)
            if not new_data:
                break
            encrypted_data += new_data
        encryptor.close()
        # encrypt all at once with new instance
        encryptor = backup.FileEncryptor(path=self.test_file, key=key)
        encrypted_data_unbuf = encryptor.read()
        encryptor.close()
        # compare the size of the encrypted data, content will differ
        # due to the random IV
        self.assertEqual(len(encrypted_data), len(encrypted_data_unbuf))

    def test_decrypt_file(self):
        """Test decryption of file"""
        key = EncryptionKey(password=self.password)
        enc_buf = backup.FileEncryptor(path=self.test_file, key=key)
        enc_buf_file = self.get_temp_file()
        buffer_size = 1024 * 10
        with open(enc_buf_file, "wb") as tfd:
            while True:
                data = enc_buf.read(buffer_size)
                if not data:
                    break
                tfd.write(data)
        enc_buf.close()
        enc_unbuf = backup.FileEncryptor(path=self.test_file, key=key)
        enc_unbuf_file = self.get_temp_file()
        with open(enc_unbuf_file, "wb") as tfd:
            while True:
                data = enc_unbuf.read()
                if not data:
                    break
                tfd.write(data)
        enc_unbuf.close()

        # decrypt
        dec_buf = backup.FileDecryptor(path=enc_buf_file, password=self.password)
        dec_buf_data = b""
        while True:
            new_data = dec_buf.read(buffer_size)
            if not new_data:
                break
            dec_buf_data += new_data
        dec_buf.close()
        dec_unbuf = backup.FileDecryptor(path=enc_unbuf_file, password=self.password)
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
        key = EncryptionKey(password=self.password)
        enc_file = self.get_temp_file()
        enc = backup.FileEncryptor(path=self.test_file, key=key)
        enc.encrypt_to_file(enc_file, overwrite=True)
        enc.close()
        # decrypt
        dec = backup.FileDecryptor(path=enc_file, password=self.password)
        dec_data = dec.read()
        dec.close()
        self.assertEqual(
            dec_data, self.test_data, "Decrypted data does not match original data"
        )

    def test_invalid_data_decryption(self):
        """Test decryption of invalid data"""
        key = EncryptionKey(password=self.password)
        enc_file = self.get_temp_file()
        enc = backup.FileEncryptor(path=self.test_file, key=key)
        enc.encrypt_to_file(enc_file, overwrite=True)
        enc.close()
        # corrupt data
        with open(enc_file, "r+b") as tfd:
            tfd.seek(0)
            tfd.write(b"invalid")
        # decrypt buffered
        dec = backup.FileDecryptor(path=enc_file, password=self.password)
        dec_data = b""
        buffer_size = 1024 * 10
        with self.assertRaises(cryptography.exceptions.InvalidTag):
            while True:
                new_data = dec.read(buffer_size)
                if not new_data:
                    break
                dec_data += new_data
        dec.close()
        # decrypt unbuffered
        dec = backup.FileDecryptor(path=enc_file, password=self.password)
        with self.assertRaises(cryptography.exceptions.InvalidTag):
            dec_data = dec.read()
        dec.close()

    def test_plaintext_not_in_encrypted_data(self):
        """Test that the plaintext is not in the encrypted data"""
        key = EncryptionKey(password=self.password)
        encryptor = backup.FileEncryptor(path=self.test_file, key=key)
        encrypted_data = encryptor.read()
        encryptor.close()
        self.assertNotEqual(encrypted_data, self.test_data)
        self.assertNotIn(self.test_data[:20], encrypted_data)

    def test_decrypt_empty_file(self):
        """Test decryption of empty file"""
        enc_file = self.get_temp_file()
        with self.assertRaises(IOError):
            backup.FileDecryptor(path=enc_file, password=self.password)

    def test_encrypt_existing_file_overwrite(self):
        """Test encryption of existing file with overwrite flag"""
        key = EncryptionKey(password=self.password)
        orig_data = b"original data"
        enc_file = self.get_temp_file()
        with open(enc_file, "wb") as tfd:
            tfd.write(orig_data)
        enc = backup.FileEncryptor(path=self.test_file, key=key)
        dest_file = self.get_temp_file()
        with self.assertRaises(OSError):
            enc.encrypt_to_file(dest_file)
        enc.close()
        enc = backup.FileEncryptor(path=self.test_file, key=key)
        enc.encrypt_to_file(dest_file, overwrite=True)
        enc.close()
        with open(dest_file, "rb") as tfd:
            enc_data = tfd.read()
        self.assertNotEqual(orig_data, enc_data)

    def test_decrypt_existing_file_overwrite(self):
        """Test decryption of existing file with overwrite flag"""
        key = EncryptionKey(password=self.password)
        enc_file = self.get_temp_file()
        enc = backup.FileEncryptor(path=self.test_file, key=key)
        enc.encrypt_to_file(enc_file, overwrite=True)
        enc.close()
        dec = backup.FileDecryptor(path=enc_file, password=self.password)
        dest_file = self.get_temp_file()
        orig_data = b"original data"
        with open(dest_file, "wb") as tfd:
            tfd.write(orig_data)
        with self.assertRaises(OSError):
            dec.decrypt_to_file(dest_file)
        dec.close()
        dec = backup.FileDecryptor(path=enc_file, password=self.password)
        dec.decrypt_to_file(dest_file, overwrite=True)
        dec.close()
        with open(dest_file, "rb") as tfd:
            dec_data = tfd.read()
        self.assertNotEqual(orig_data, dec_data)

    def test_filename_too_long_for_encryption(self):
        """Test that a filename that is too long for encryption raises an error"""
        filename = "x" * (backup.MAX_FILENAME_LENGTH + 1)
        key = EncryptionKey(password=self.password)
        with self.assertRaises(ValueError):
            backup.encrypt_filename(key, filename)


class FileNameEncryptionTest(unittest.TestCase):
    """Test encryption of filenames"""

    def test_encrypt_filename(self):
        """Test encryption of filename"""
        password = "test"
        key = EncryptionKey(password=password)
        filename = "test.txt"
        encrypted_name = backup.encrypt_filename(key, filename)
        self.assertNotEqual(filename, encrypted_name)
        self.assertEqual(
            filename, backup.decrypt_filename(encrypted_name, password=password)
        )

    def test_decrypt_corrupted_filename(self):
        """Test decryption of corrupted filename"""
        password = "test"
        key = EncryptionKey(password=password)
        filename = "test.txt"
        encrypted_name = backup.encrypt_filename(key, filename)
        raw = base64.urlsafe_b64decode(encrypted_name)
        raw = raw[:10] + b"INVALID" + raw[10:]
        encrypted_name = base64.urlsafe_b64encode(raw)

        with self.assertRaises(cryptography.exceptions.InvalidTag):
            backup.decrypt_filename(encrypted_name, password=password)

    def test_decrypt_too_short(self):
        """Test decryption of too short filename"""
        filename = b"test"
        invalid_crypto_data = base64.urlsafe_b64encode(filename)
        with self.assertRaises(ValueError):
            backup.decrypt_filename(invalid_crypto_data, password="test")

    def test_filename_too_long(self):
        """Test that a filename that is too long for encryption raises an error"""
        filename = "x" * (backup.MAX_UNENCRYPTED_FILENAME_LENGTH + 1)
        with self.assertRaises(ValueError):
            backup.encrypt_filename(EncryptionKey(password="test"), filename)

    def test_filename_at_max_length(self):
        """Test that a filename at the max length is encrypted"""
        filename = "x" * backup.MAX_UNENCRYPTED_FILENAME_LENGTH
        encrypted = backup.encrypt_filename(EncryptionKey(password="test"), filename)
        self.assertNotEqual(filename, encrypted)
        self.assertEqual(filename, backup.decrypt_filename(encrypted, password="test"))


class DirectoryEncryptionTest(unittest.TestCase):
    """Test encryption of directories"""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="backup-test-")
        self.source_dir = os.path.join(self.root, "source")
        self.encrypted_dir = os.path.join(self.root, "encrypted")
        self.decrypted_dir = os.path.join(self.root, "decrypted")
        self.password = "test"
        os.mkdir(self.source_dir)
        os.mkdir(self.encrypted_dir)
        os.mkdir(self.decrypted_dir)

    def tearDown(self):
        shutil.rmtree(self.root)

    def create_fs_tree(self, root, depth=2, files_per_dir=3, dirs_per_dir=2):
        """Create a directory tree for testing"""
        for i in range(files_per_dir):
            fname = os.path.join(root, f"file-{depth}-{i}")
            with open(fname, "w", encoding="utf-8") as tfd:
                tfd.write(fname)
        for i in range(dirs_per_dir):
            dname = os.path.join(root, f"dir-{depth}-{i}")
            os.mkdir(dname)
            if depth > 0:
                self.create_fs_tree(
                    root=dname,
                    depth=depth - 1,
                    files_per_dir=files_per_dir,
                    dirs_per_dir=dirs_per_dir,
                )

    def test_encrypt_empty_directory(self):
        """Test encryption of empty directory"""
        backup.encrypt_directory(
            self.source_dir, self.encrypted_dir, password=self.password
        )
        _, dirs, files = next(os.walk(self.encrypted_dir))
        self.assertEqual(dirs, [])
        self.assertEqual(files, [])

    def test_encrypt_directory(self):
        """Test encryption of directory"""
        self.create_fs_tree(self.source_dir)
        backup.encrypt_directory(
            self.source_dir, self.encrypted_dir, password=self.password
        )
        # check that number of files on each level is the same
        # and that the content is not the same (i.e. encrypted)
        source_walker = os.walk(self.source_dir)
        encrypted_walker = os.walk(self.encrypted_dir)
        while True:
            try:
                source_root, source_dirs, source_files = next(source_walker)
                encrypted_root, encrypted_dirs, encrypted_files = next(encrypted_walker)
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
        self.create_fs_tree(self.source_dir)
        backup.encrypt_directory(
            self.source_dir, self.encrypted_dir, password=self.password
        )
        backup.decrypt_directory(
            self.encrypted_dir, self.decrypted_dir, password=self.password
        )
        source_walker = os.walk(self.source_dir)
        decrypted_walker = os.walk(self.decrypted_dir)
        while True:
            try:
                source_root, source_dirs, source_files = next(source_walker)
                decrypted_root, decrypted_dirs, decrypted_files = next(decrypted_walker)
            except StopIteration:
                break
            self.assertEqual(len(source_files), len(decrypted_files))
            self.assertEqual(len(source_dirs), len(decrypted_dirs))
            for source_file, decrypted_file in zip(source_files, decrypted_files):
                with open(os.path.join(source_root, source_file), "rb") as tfd:
                    source_data = tfd.read()
                with open(os.path.join(decrypted_root, decrypted_file), "rb") as tfd:
                    decrypted_data = tfd.read()
                self.assertEqual(
                    source_data, decrypted_data, "Decrypted data does not match source"
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
        dir_name_size = (
            backup.MAX_UNENCRYPTED_FILENAME_LENGTH
        )  # length of directory name
        # long enough but not too much for os.makedirs
        depth = int((backup.MAX_PATH_LENGTH - current_path_length) / dir_name_size) - 1
        dirtree = "/".join(
            [str(_) + "x" * (dir_name_size - len(str(_))) for _ in range(depth)]
        )
        last_dir = os.path.join(source_dir, dirtree)
        os.makedirs(last_dir)
        filename = "f" * backup.MAX_UNENCRYPTED_FILENAME_LENGTH
        os.chdir(last_dir)
        os.makedirs(dirtree)  # double the "long enough", so it's definitely too much :)
        os.chdir(dirtree)
        log.debug(f"Current dir length: {len(os.getcwd())}")
        with open(filename, "wb") as tfd:
            tfd.write(b"test")
        abs_filename = os.path.join(os.getcwd(), filename)
        log.debug(f"Abs path length of test filename: {len(abs_filename)}")
        backup.encrypt_directory(source_dir, dest_dir, password=self.password)
        backup.decrypt_directory(dest_dir, dec_dir, password=self.password)

        source_walker = os.walk(source_dir)
        decrypted_walker = os.walk(dec_dir)
        while True:
            try:
                source_root, source_dirs, source_files = next(source_walker)
                decrypted_root, decrypted_dirs, decrypted_files = next(decrypted_walker)
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


class DirectoryComparisonTest(unittest.TestCase):
    """Test directory comparison"""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="backup-test-")
        self.source_dir = os.path.join(self.root, "source")
        self.encrypted_dir = os.path.join(self.root, "encrypted")
        self.decrypted_dir = os.path.join(self.root, "decrypted")
        self.password = "test"
        os.mkdir(self.source_dir)
        os.mkdir(self.encrypted_dir)
        os.mkdir(self.decrypted_dir)

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_compare_same_directory(self):
        """test identical dirs"""
        newdir = "newdir"
        dir1 = FSDirectory(self.source_dir)
        dir2 = FSDirectory(self.source_dir)
        self.assertIsNone(
            dir1.one_way_diff(dir2), "No difference expected on identical directories"
        )
        os.mkdir(os.path.join(self.source_dir, newdir))
        self.assertIsNone(
            dir1.one_way_diff(dir2), "No difference expected on identical directories"
        )

    def test_commpare_identical_directories_encrypted(self):
        """test identical encrypted dirs"""
        password = "test"
        os.mkdir(os.path.join(self.source_dir, "newdir"))
        with open(os.path.join(self.source_dir, "file"), "wb") as tfd:
            tfd.write(b"test")
        with open(os.path.join(self.source_dir, "newdir", "file2"), "wb") as tfd:
            tfd.write(b"test2")
        backup.encrypt_directory(self.source_dir, self.encrypted_dir, password=password)
        dir1 = FSDirectory.from_filesystem(self.encrypted_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
        self.assertIsNone(
            dir1.one_way_diff(dir2),
            "No difference expected on identical encrypted directories",
        )

    def test_extra_source_directory(self):
        """test extra directory in target"""
        new_dir = "new_dir"
        os.mkdir(os.path.join(self.encrypted_dir, new_dir))
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
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
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
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
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
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
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
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
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
        self.assertIsNone(
            dir1.one_way_diff(dir2), "No difference expected on identical directories"
        )

    def test_two_extra_empty_directories(self):
        """test two extra empty directories in target"""
        dir1 = "dir1"
        dir2 = "dir2"
        os.mkdir(os.path.join(self.encrypted_dir, dir1))
        os.mkdir(os.path.join(self.encrypted_dir, dir2))
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
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
        password = "test"
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        backup.encrypt_directory(self.source_dir, self.encrypted_dir, password)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
        diff = dir1.one_way_diff(dir2)
        self.assertIsNone(diff, "No difference expected on identical directories")

    def test_sub_operator(self):
        """test sub operator"""
        os.mkdir(os.path.join(self.encrypted_dir, "dir1"))
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
        diff = dir2 - dir1
        self.assertIsNotNone(diff, "Difference expected on different directories")
        diff2 = dir1.one_way_diff(dir2)
        self.assertIsNotNone(diff2, "Difference expected on different directories")
        self.assertIn("dir1", diff.dir_names(), "dir1 expected in diff")
        self.assertIn("dir1", diff2.dir_names(), "dir1 expected in diff2")

    def test_eq_operator(self):
        """test eq operator"""
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
        self.assertEqual(dir1, dir2, "Directories should be equal")
        # extra dir in target
        os.mkdir(os.path.join(self.encrypted_dir, "newdir"))
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
        self.assertNotEqual(dir1, dir2, "Directories should not be equal")
        os.rmdir(os.path.join(self.encrypted_dir, "newdir"))
        # extra dir in source
        os.mkdir(os.path.join(self.source_dir, "newdir"))
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
        self.assertNotEqual(dir1, dir2, "Directories should not be equal")
        os.rmdir(os.path.join(self.source_dir, "newdir"))
        # extra file in target
        with open(
            os.path.join(self.encrypted_dir, "newfile"), "w", encoding="utf-8"
        ) as tfd:
            tfd.write("test")
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
        self.assertNotEqual(dir1, dir2, "Directories should not be equal")
        os.remove(os.path.join(self.encrypted_dir, "newfile"))
        # extra file in source
        with open(
            os.path.join(self.source_dir, "newfile"), "w", encoding="utf-8"
        ) as tfd:
            tfd.write("test")
        dir1 = FSDirectory.from_filesystem(self.source_dir)
        dir2 = FSDirectory.from_filesystem(self.encrypted_dir)
        self.assertNotEqual(dir1, dir2, "Directories should not be equal")
        os.remove(os.path.join(self.source_dir, "newfile"))


class FSDirectoryTest(unittest.TestCase):
    """Tests for FSDirectory class"""

    def test_add_str_instead_of_dir(self):
        """test adding string instead of FSDirectory object"""
        dir1 = FSDirectory(name="root")
        with self.assertRaises(TypeError):
            dir1.add_directory("dir1")

    def test_duplicit_dir_add(self):
        """test adding directory with same name as existing one"""
        dir1 = FSDirectory(name="root")
        dir1.add_directory(FSDirectory("dir1"))
        with self.assertRaises(
            ValueError, msg="Adding already existing name should raise ValueError"
        ):
            dir1.add_directory(FSDirectory("dir1"))

    def test_add_str_instead_of_file(self):
        """test adding string instead of FSFile object"""
        dir1 = FSDirectory(name="root")
        with self.assertRaises(TypeError):
            dir1.add_file("file1")

    def test_add_duplicit_file(self):
        """test adding file with same name as existing one"""
        dir1 = FSDirectory(name="root")
        dir1.add_file(FSFile("file1"))
        with self.assertRaises(
            ValueError, msg="Adding already existing name should raise ValueError"
        ):
            dir1.add_file(FSFile("file1"))

    def test_add_file_with_same_name_as_dir(self):
        """test adding file with same name as existing directory"""
        dir1 = FSDirectory(name="root")
        dir1.add_directory(FSDirectory("dir1"))
        with self.assertRaises(
            ValueError, msg="Adding already existing name should raise ValueError"
        ):
            dir1.add_file(FSFile("dir1"))

    def test_add_dir_with_same_name_as_file(self):
        """test adding directory with same name as existing file"""
        dir1 = FSDirectory(name="root")
        dir1.add_file(FSFile("file1"))
        with self.assertRaises(
            ValueError, msg="Adding already existing name should raise ValueError"
        ):
            dir1.add_directory(FSDirectory("file1"))


if __name__ == "__main__":
    unittest.main()
