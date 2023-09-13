# Encrypted Backup

This tool takes file system structure and creates its encrypted version (both filenames and data are encrypted). The encrypted version can be then stored anywhere without a need for other protection.

By default it skips files that are already present in the encrypted structure (name check only, no attributes).

Optionally supports AWS S3 (requires s3fs and proper aws setup - roles/keys/etc.).

Uses AES256 in GCM mode with password derived key ([scrypt](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt))

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install required runtime environment.

```bash
pip install -r requirements.txt
```

## Usage
### Encrypt

```bash
$ tree /tmp/test/source
/tmp/test/source
├── dir-01
│   └── dirfile.txt
└── file.txt

$ ./backup.py --encrypt /tmp/test/source /tmp/test/encrypted
Password: 
Encrypting file /tmp/test/source/file.txt
Encrypting file /tmp/test/source/dir-01/dirfile.txt

Encryption successfully finished. Encrypted files: 2 Skipped files: 0

$ tree /tmp/test/encrypted
/tmp/test/encrypted
├── ABwbyDMwPoRpudXG-4sWirmnmIr8ykdCEbixshJVU2YpAm4xX-g2D78F-YFqs6fdLspc
│   └── ALSLdzU-fkGZyeogSQIzl0RRMIbYjp52dZpYeDxVU2YpAm4xX-g2D78F-YFqqhL7GbK1zFN6IhI.
└── AImTvmzduZnVXEomc-3zlLm0T4qzrIOYv_xT5W1VU2YpAm4xX-g2D78F-YFqYwjWmXajMGg.
```
### List encrypted content
```bash
$ ./backup.py --list /tmp/test/encrypted
Password: 
/tmp/test/encrypted/dir-01
/tmp/test/encrypted/dir-01/dirfile.txt
/tmp/test/encrypted/file.txt
```

### Decrypt
```bash
$ ./backup.py --decrypt /tmp/test/encrypted /tmp/test/decrypted
Password: 
Decrypting file /tmp/test/encrypted/AImTvmzduZnVXEomc-3zlLm0T4qzrIOYv_xT5W1VU2YpAm4xX-g2D78F-YFqYwjWmXajMGg.
Decrypting file /tmp/test/encrypted/ABwbyDMwPoRpudXG-4sWirmnmIr8ykdCEbixshJVU2YpAm4xX-g2D78F-YFqs6fdLspc/ALSLdzU-fkGZyeogSQIzl0RRMIbYjp52dZpYeDxVU2YpAm4xX-g2D78F-YFqqhL7GbK1zFN6IhI.

Encryption successfully finished. Decrypted files: 2 Skipped files: 0

$ tree /tmp/test/decrypted
/tmp/test/decrypted
├── dir-01
│   └── dirfile.txt
└── file.txt
```
### Encrypt new files only
```bash
$ echo moresecrets > /tmp/test/source/newfile.txt
$ ./backup.py --encrypt /tmp/test/source /tmp/test/encrypted
Password: 
Encrypting file /tmp/test/source/newfile.txt
Skipping file/dir (already encrypted in target): /tmp/test/source/file.txt
Skipping file/dir (already encrypted in target): /tmp/test/source/dir-01/dirfile.txt

Encryption successfully finished. Encrypted files: 1 Skipped files: 2

```

### S3 encryption
```bash
$ ./backup.py --profile rolesanywhere --encrypt /tmp/test/source s3://jk-encrypted-backup-ci/encrypted 
Password: 
Encrypting file /tmp/test/source/file.txt
Encrypting file /tmp/test/source/newfile.txt
Encrypting file /tmp/test/source/dir-01/dirfile.txt

Encryption successfully finished. Encrypted files: 3 Skipped files: 0

```
### S3 listing
```bash
 ./backup.py --profile rolesanywhere --list s3://jk-encrypted-backup-ci/encrypted  -v
INFO:__main__:Setting scrypt_n to 1048576
Password: 
/encrypted/dir-01  ->  /encrypted/AMZ0yd5TTgEaficJXy3Aq0neISl8xlnvzgUJA5Fr0AG2OM7tZc9B9_GWNXKP3vVUdz8t
/encrypted/dir-01/dirfile.txt  ->  /encrypted/AMZ0yd5TTgEaficJXy3Aq0neISl8xlnvzgUJA5Fr0AG2OM7tZc9B9_GWNXKP3vVUdz8t/APxnf7pKdtn9dAf2c422ZpNOgs42N3QXpn4p9nJr0AG2OM7tZc9B9_GWNXKPmgINOh77hFh5GMw.
/encrypted/file.txt  ->  /encrypted/AOBvLjhHRqo516ZUm-CgIMBtSvf5uQosh4tVK5Fr0AG2OM7tZc9B9_GWNXKPCU76TTRnCzs.
/encrypted/newfile.txt  ->  /encrypted/AOZJBaN9OAaJeGtbIlkduhiFTTjiYZLdmI0nBjZr0AG2OM7tZc9B9_GWNXKPmf3cqD8DFQ1VmRE.

```

### S3 decryption
```
$ ./backup.py --profile rolesanywhere --decrypt s3://jk-encrypted-backup-ci/encrypted  /tmp/test/s3decrypted
Password: 
Decrypting file /encrypted/AOBvLjhHRqo516ZUm-CgIMBtSvf5uQosh4tVK5Fr0AG2OM7tZc9B9_GWNXKPCU76TTRnCzs.
Decrypting file /encrypted/AOZJBaN9OAaJeGtbIlkduhiFTTjiYZLdmI0nBjZr0AG2OM7tZc9B9_GWNXKPmf3cqD8DFQ1VmRE.
Decrypting file /encrypted/AMZ0yd5TTgEaficJXy3Aq0neISl8xlnvzgUJA5Fr0AG2OM7tZc9B9_GWNXKP3vVUdz8t/APxnf7pKdtn9dAf2c422ZpNOgs42N3QXpn4p9nJr0AG2OM7tZc9B9_GWNXKPmgINOh77hFh5GMw.

Encryption successfully finished. Decrypted files: 3 Skipped files: 0
```

## Limitations
- File size <= 64G
- File names length - 144 characters (bytes)
- Full path lenght for S3 backups - the whorle encrypted path must be < 1024 chars

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

GPLv3