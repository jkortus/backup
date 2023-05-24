import os
import backup
import unittest
from backup import EncryptionKey
import tempfile
import cryptography.exceptions
import base64
import shutil
import logging

backup.log.setLevel(backup.logging.ERROR)

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class EncryptionKeyTest(unittest.TestCase):
    def test_new_key(self):
        password = "test"
        key = EncryptionKey(password=password)
        self.assertEqual(len(key.key), 32)
        self.assertEqual(len(key.salt), backup.SALT_SIZE_BYTES)

    def test_key_from_salt(self):
        password = "test"
        key = EncryptionKey(password=password)
        key2 = EncryptionKey(password=password, salt=key.salt)
        self.assertEqual(key.key, key2.key)
        self.assertEqual(key.salt, key2.salt)


class FileEncryptorTest(unittest.TestCase):
    def setUp(self):
        self.created_files = []
        self.test_dir = tempfile.mkdtemp(prefix="backup_test_")
        self.test_file = self.get_temp_file()
        self.test_data = b"test" * 1024 * 1024
        with open(self.test_file, "wb") as tfd:
            tfd.write(self.test_data)
        self.password = "test"

    def add_file(self, path):
        self.created_files.append(path)

    def get_temp_file(self):
        fd, path = tempfile.mkstemp(dir=self.test_dir)
        os.close(fd)
        self.add_file(path)
        return path

    def tearDown(self):
        for f in self.created_files:
            os.remove(os.path.join(self.test_dir, f))
        os.rmdir(self.test_dir)

    def test_encrypt_file(self):
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
        self.assertEqual(dec_buf_data, dec_unbuf_data, "Buffered and unbuffered decryption do not match")
        self.assertEqual(dec_buf_data, self.test_data, "Decrypted data does not match original data")

    def test_encrypt_to_file(self):
        key = EncryptionKey(password=self.password)
        enc_file = self.get_temp_file()
        enc = backup.FileEncryptor(path=self.test_file, key=key)
        enc.encrypt_to_file(enc_file)
        enc.close()
        # decrypt
        dec = backup.FileDecryptor(path=enc_file, password=self.password)
        dec_data = dec.read()
        dec.close()
        self.assertEqual(dec_data, self.test_data, "Decrypted data does not match original data")

    def test_invalid_data_decryption(self):
        key = EncryptionKey(password=self.password)
        enc_file = self.get_temp_file()
        enc = backup.FileEncryptor(path=self.test_file, key=key)
        enc.encrypt_to_file(enc_file)
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
        key = EncryptionKey(password=self.password)
        encryptor = backup.FileEncryptor(path=self.test_file, key=key)
        encrypted_data = encryptor.read()
        encryptor.close()
        self.assertNotEqual(encrypted_data, self.test_data)
        self.assertNotIn(self.test_data[:20], encrypted_data)

    def test_decrypt_empty_file(self):
        key = EncryptionKey(password=self.password)
        enc_file = self.get_temp_file()
        with self.assertRaises(IOError):
            backup.FileDecryptor(path=enc_file, password=self.password)


class FileNameEncryptionTest(unittest.TestCase):
    def test_encrypt_filename(self):
        password = "test"
        key = EncryptionKey(password=password)
        filename = "test.txt"
        encrypted_name = backup.encrypt_filename(key, filename)
        self.assertNotEqual(filename, encrypted_name)
        self.assertEqual(
            filename, backup.decrypt_filename(encrypted_name, password=password)
        )

    def test_decrypt_corrupted_filename(self):
        password = "test"
        key = EncryptionKey(password=password)
        filename = "test.txt"
        encrypted_name = backup.encrypt_filename(key, filename)
        encrypted_name = b"INVALID" + encrypted_name[7:]
        with self.assertRaises(cryptography.exceptions.InvalidTag):
            backup.decrypt_filename(encrypted_name, password=password)

    def test_decrypt_too_short(self):
        filename = b"test"
        invalid_crypto_data = base64.urlsafe_b64encode(filename)
        with self.assertRaises(ValueError):
            backup.decrypt_filename(invalid_crypto_data, password="test")

    def test_filename_too_long(self):
        filename = "x" * (backup.MAX_UNENCRYPTED_FILENAME_LENGTH + 1)
        with self.assertRaises(ValueError):
            backup.encrypt_filename(EncryptionKey(password="test"), filename)


class DirectoryEncryptionTest(unittest.TestCase):
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
        for i in range(files_per_dir):
            fname = os.path.join(root, f"file-{depth}-{i}")
            with open(fname, "w") as tfd:
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
        backup.encrypt_directory(
            self.source_dir, self.encrypted_dir, password=self.password
        )
        _, dirs, files = next(os.walk(self.encrypted_dir))
        self.assertEqual(dirs, [])
        self.assertEqual(files, [])

    def test_encrypt_directory(self):
        self.create_fs_tree(self.source_dir)
        backup.encrypt_directory(
            self.source_dir, self.encrypted_dir, password=self.password
        )
        _, dirs, files = next(os.walk(self.encrypted_dir))
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
                self.assertNotEqual(source_data, encrypted_data, "Source data found in encrypted file")

    def test_decrypt_directory(self):
        ''' encrypt, decrypt and compare with source for one-to-one match across the tree'''
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
                decrypted_root, decrypted_dirs, decrypted_files = next(
                    decrypted_walker
                )
            except StopIteration:
                break
            self.assertEqual(len(source_files), len(decrypted_files))
            self.assertEqual(len(source_dirs), len(decrypted_dirs))
            for source_file, decrypted_file in zip(source_files, decrypted_files):
                with open(os.path.join(source_root, source_file), "rb") as tfd:
                    source_data = tfd.read()
                with open(os.path.join(decrypted_root, decrypted_file), "rb") as tfd:
                    decrypted_data = tfd.read()
                self.assertEqual(source_data, decrypted_data, "Decrypted data does not match source")


        



if __name__ == "__main__":
    unittest.main()
