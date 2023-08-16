#!/usr/bin/env python3

""" Backup tool command line utility."""
import argparse
import logging
import sys
import base
from base import FSDirectory, init_password
import filesystems
from filesystems import RealFilesystem

logging.basicConfig()

log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)

# pylint: disable=broad-except
# pylint: disable=logging-fstring-interpolation
# pylint: disable=logging-not-lazy


def init_s3_from_string(s3_string, profile):
    """
    Parses s3://bucket/path string and returns AWSFilesystem instance
    usable as source or target filesystem
    Returns: filesystem, path
    """
    try:
        import awsfilesystem  # pylint: disable=import-outside-toplevel
    except ImportError as ex:
        log.error(
            "AWSFilesystem not available. Most likely s3fs module is not installed."
        )
        log.error("Exact error: " + str(ex))
        sys.exit(2)
    parts = s3_string.split("/")
    if len(parts) < 3:
        log.error("Invalid s3 string: " + s3_string)
        sys.exit(2)
    bucket = parts[2]
    log.debug(f"S3 detected, using bucket {bucket} and profile {profile}")
    return awsfilesystem.AWSFilesystem(bucket, profile), "/" + "/".join(parts[3:])


def main():
    """Main function"""
    # parse cmdline args
    parser = argparse.ArgumentParser(
        description="Encrypt / decrypt source directory to target directory."
    )
    parser.add_argument(
        "--encrypt",
        nargs=2,
        metavar=("SOURCE", "TARGET"),
        help="encrypt SOURCE to TARGET",
    )
    parser.add_argument(
        "--decrypt",
        nargs=2,
        metavar=("SOURCE", "TARGET"),
        help="decrypt SOURCE to TARGET",
    )
    parser.add_argument("-l", "--list", nargs=1, metavar=("SOURCE"), help="list SOURCE")

    parser.add_argument(
        "-p", "--password", metavar="password", type=str, help="password", default=None
    )
    parser.add_argument("--debug", action="store_true", help="debug mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode")
    parser.add_argument(
        "--profile", metavar="profile", type=str, help="aws profile", default=None
    )
    args = parser.parse_args()

    base.log.setLevel(logging.WARNING)

    if args.verbose:
        base.log.setLevel(logging.INFO)

    if args.debug:
        base.log.setLevel(logging.DEBUG)
        log.setLevel(logging.DEBUG)
        filesystems.log.setLevel(logging.DEBUG)

    status_reporter = base.StatusReporter()
    base.STATUS_REPORTER = status_reporter

    if args.encrypt:
        source_filesystem = RealFilesystem()
        source_dir = args.encrypt[0]
        target_filesystem = RealFilesystem()
        target_dir = args.encrypt[1]
        if args.encrypt[0].startswith("s3://"):
            source_filesystem, source_dir = init_s3_from_string(
                args.encrypt[0], args.profile
            )
        if args.encrypt[1].startswith("s3://"):
            target_filesystem, target_dir = init_s3_from_string(
                args.encrypt[1], args.profile
            )
        init_password(args.password)
        try:
            if not target_filesystem.exists(target_dir):
                target_filesystem.makedirs(target_dir)
            base.encrypt_directory(
                FSDirectory.from_filesystem(source_dir, filesystem=source_filesystem),
                FSDirectory.from_filesystem(target_dir, filesystem=target_filesystem),
            )
            print(
                f"\nEncryption successfully finished. "
                f"Encrypted files: {status_reporter.files_processed}"
                f" Skipped files: {status_reporter.files_skipped}"
            )
        except Exception as ex:
            log.debug(f"Exception: {ex}", exc_info=True)
            log.error("Error: " + str(ex))
            sys.exit(2)

    elif args.decrypt:
        source_filesystem = RealFilesystem()
        source_dir = args.decrypt[0]
        target_filesystem = RealFilesystem()
        target_dir = args.decrypt[1]
        if args.decrypt[0].startswith("s3://"):
            source_filesystem, source_dir = init_s3_from_string(
                args.decrypt[0], args.profile
            )
        if args.decrypt[1].startswith("s3://"):
            target_filesystem, target_dir = init_s3_from_string(
                args.decrypt[1], args.profile
            )

        init_password(args.password)
        if not target_filesystem.exists(target_dir):
            target_filesystem.makedirs(target_dir)
        try:
            base.decrypt_directory(
                FSDirectory.from_filesystem(source_dir, filesystem=source_filesystem),
                FSDirectory.from_filesystem(target_dir, filesystem=target_filesystem),
            )
            print(
                f"\nEncryption successfully finished. "
                f"Decrypted files: {status_reporter.files_processed}"
                f" Skipped files: {status_reporter.files_skipped}"
            )
        except Exception as ex:
            log.exception(ex)
            print("Error: " + str(ex), file=sys.stderr)
            sys.exit(2)
    elif args.list:
        source_filesystem = RealFilesystem()
        source_dir = args.list[0]
        if args.list[0].startswith("s3://"):
            source_filesystem, source_dir = init_s3_from_string(
                args.list[0], args.profile
            )

        init_password(args.password)
        try:
            directory = FSDirectory.from_filesystem(
                source_dir, filesystem=source_filesystem
            )
            directory.pretty_print()

        except Exception as ex:
            log.debug(f"Exception: {ex}", exc_info=True)
            log.error(ex)
            sys.exit(2)

    else:
        log.error("No action specified")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
