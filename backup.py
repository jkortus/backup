#!/usr/bin/env python3

""" Backup tool command line utility."""
import argparse
import logging
import sys
import base

logging.basicConfig(level=logging.WARNING)

log = logging.getLogger(__name__)

# pylint: disable=broad-except


def main():
    """Main function"""
    # parse cmdline args
    parser = argparse.ArgumentParser(
        description="Encrypt source directory to target directory."
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
    parser.add_argument("--ls", nargs=1, metavar=("SOURCE"), help="list SOURCE")

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

    if not args.password:
        args.password = base.get_password()
    status_reporter = base.StatusReporter()
    if args.encrypt:
        try:
            base.encrypt_directory(
                args.encrypt[0], args.encrypt[1], args.password, status_reporter
            )
            print(
                f"\nEncryption successfully finished. "
                f"Encrypted files: {status_reporter.files_processed}"
                f" Skipped files: {status_reporter.files_skipped}"
            )
        except Exception as ex:
            log.debug(f"Exception: {ex}", exc_info=True)
            print("Error: " + str(ex), file=sys.stderr)
            sys.exit(2)
    elif args.decrypt:
        try:
            base.decrypt_directory(args.decrypt[0], args.decrypt[1], args.password)
            print("Decryption successfully finished.")
        except Exception as ex:
            log.exception(ex)
            print("Error: " + str(ex), file=sys.stderr)
            sys.exit(2)
    elif args.ls:
        try:
            directory = base.FSDirectory.from_filesystem(args.ls[0])
            directory.pretty_print()

        except Exception as ex:
            log.exception(ex)
            sys.exit(2)

    else:
        log.error("Invalid operation: %s", args.operation)
        sys.exit(1)


if __name__ == "__main__":
    main()
