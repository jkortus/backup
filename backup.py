#!/usr/bin/env python3

""" Backup tool command line utility."""
import argparse
import logging
import sys
import os
from shutil import get_terminal_size
import base
from base import FSDirectory, init_password
from filesystems import RealFilesystem

logging.basicConfig()

log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)

# pylint: disable=broad-except
# pylint: disable=logging-fstring-interpolation
# pylint: disable=logging-not-lazy


def init_s3_from_string(
    s3_string: str, profile: str
) -> "awsfilesystem.AWSFilesystem":  # type: ignore[name-defined]
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
    # process this amount of data in one upload/download loop
    base.BUFFER_SIZE_BYTES = 1024 * 1024 * 20  # 20 MB
    return awsfilesystem.AWSFilesystem(bucket, profile), "/" + "/".join(parts[3:])


def _change_all_loggers_level(level: int) -> None:
    """Change all loggers level"""
    # pylint: disable=no-member
    loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
    for logger in loggers:
        log.debug(f"Setting {logger.name} to {level}")
        logger.setLevel(level)


def _setup_logging(args: argparse.Namespace) -> None:
    """Setup logging"""

    if args.verbose:
        _change_all_loggers_level(logging.INFO)
        # log.setLevel(logging.INFO)
        # base.log.setLevel(logging.INFO)

    if args.debug:
        log.setLevel(logging.DEBUG)
        base.log.setLevel(logging.DEBUG)

    if args.debug_all:
        # pylint: disable=no-member
        loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
        for logger in loggers:
            logger.setLevel(logging.DEBUG)


# pylint: disable=too-many-branches
# pylint: disable=too-many-statements
def main() -> None:
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
    parser.add_argument("--debug-all", action="store_true", help="extreme debug mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode")
    parser.add_argument(
        "--profile", metavar="profile", type=str, help="aws profile", default=None
    )
    parser.add_argument(
        "--scrypt-n",
        type=int,
        help="Key strength modificator for scrypt. Don't change it if you don't "
        f"understand it and use default value ({base.SCRYPT_N}). It might be "
        f"useful to lower this value for testing ({2**14}) to sacrifice "
        "security for speed.",
        default=base.SCRYPT_N,
    )
    args = parser.parse_args()

    _setup_logging(args)

    status_reporter = base.StatusReporter(terminal_width=get_terminal_size()[0])
    base.STATUS_REPORTER = status_reporter

    if args.scrypt_n is not None:
        log.info(f"Setting scrypt_n to {args.scrypt_n}")
        base.SCRYPT_N = args.scrypt_n

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
        _setup_logging(args)  # again due to possible s3 imports
        init_password(args.password)
        try:
            if not source_filesystem.exists(source_dir):
                log.error(f"Source directory {source_dir} does not exist.")
                sys.exit(1)
            if not target_filesystem.exists(target_dir):
                target_filesystem.makedirs(target_dir)
            if target_filesystem.is_dir(source_dir):
                base.encrypt_directory(
                    FSDirectory.from_filesystem(
                        source_dir, filesystem=source_filesystem
                    ),
                    FSDirectory.from_filesystem(
                        target_dir, filesystem=target_filesystem
                    ),
                )
            else:
                # assume source_dir is a file
                fname = os.path.basename(source_dir)
                encrypted_dir = FSDirectory.from_filesystem(
                    target_dir, filesystem=target_filesystem, recursive=False
                )
                if fname in encrypted_dir.file_names():
                    log.error(
                        f"File {source_dir} already exists in {target_dir}. "
                        "Please delete it first."
                    )
                    sys.exit(1)
                base.encrypt_file(
                    source_dir, source_filesystem, target_dir, target_filesystem
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
        _setup_logging(args)  # again due to possible s3 imports
        init_password(args.password, confirm=False)
        try:
            if not source_filesystem.exists(source_dir):
                log.error(f"Source directory {source_dir} does not exist")
                sys.exit(1)
            if not target_filesystem.exists(target_dir):
                target_filesystem.makedirs(target_dir)

            if source_filesystem.is_dir(source_dir):
                base.decrypt_directory(
                    FSDirectory.from_filesystem(
                        source_dir, filesystem=source_filesystem
                    ),
                    FSDirectory.from_filesystem(
                        target_dir, filesystem=target_filesystem
                    ),
                )
            else:
                # assume it's a file
                base.decrypt_file(
                    source_dir, source_filesystem, target_dir, target_filesystem
                )

            print(
                f"\nEncryption successfully finished. "
                f"Decrypted files: {status_reporter.files_processed}"
                f" Skipped files: {status_reporter.files_skipped}"
            )
        except Exception as ex:
            log.debug(ex, exc_info=True)
            print("Error: " + str(ex), file=sys.stderr)
            sys.exit(2)
    elif args.list:
        source_filesystem = RealFilesystem()
        source_dir = args.list[0]
        if args.list[0].startswith("s3://"):
            source_filesystem, source_dir = init_s3_from_string(
                args.list[0], args.profile
            )
        _setup_logging(args)  # again due to possible s3 imports
        init_password(args.password)
        try:
            directory = FSDirectory.from_filesystem(
                source_dir, filesystem=source_filesystem
            )
            for entry in directory.to_path_list():
                if args.verbose:
                    print(entry[0], " -> ", entry[1])
                else:
                    print(entry[0])

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
