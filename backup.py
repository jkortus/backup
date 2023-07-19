#!/usr/bin/env python3

""" Backup tool command line utility."""
import argparse
import logging
import sys
import base
from base import FSDirectory
from filesystems import RealFilesystem

logging.basicConfig()

log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)

# pylint: disable=broad-except


def set_password(password):
    """
    helper function to set password in base module
    and not duplicate code in main function
    """
    if not password:
        password = base.get_password()
    # TODO: private member should not be accessed directly
    base._PASSWORD = password


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
        "-p", "--password", metavar="password", type=str, help="password", default=""
    )
    parser.add_argument("--debug", action="store_true", help="debug mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode")
    args = parser.parse_args()

    base.log.setLevel(logging.WARNING)

    if args.verbose:
        base.log.setLevel(logging.INFO)

    if args.debug:
        base.log.setLevel(logging.DEBUG)

    status_reporter = base.StatusReporter()
    base.STATUS_REPORTER = status_reporter
    # real filesystem hardcoded now temporarily
    source_filesystem = RealFilesystem()
    target_filesystem = RealFilesystem()
    if args.encrypt:
        set_password(args.password)
        try:
            if not target_filesystem.exists(args.encrypt[1]):
                target_filesystem.makedirs(args.encrypt[1])
            base.encrypt_directory(
                FSDirectory.from_filesystem(
                    args.encrypt[0], filesystem=source_filesystem
                ),
                FSDirectory.from_filesystem(
                    args.encrypt[1], filesystem=target_filesystem
                ),
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
        set_password(args.password)
        if not target_filesystem.exists(args.decrypt[1]):
            target_filesystem.makedirs(args.decrypt[1])
        try:
            base.decrypt_directory(
                FSDirectory.from_filesystem(
                    args.decrypt[0], filesystem=source_filesystem
                ),
                FSDirectory.from_filesystem(
                    args.decrypt[1], filesystem=target_filesystem
                ),
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
        set_password(args.password)
        try:
            directory = FSDirectory.from_filesystem(
                args.list[0], filesystem=source_filesystem
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
