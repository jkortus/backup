""" Module for filesystems interactions"""
import os
import pathlib
import logging
from contextlib import contextmanager
from abc import ABC, abstractmethod
from typing import Generator, IO, AnyStr

# pylint: disable=logging-fstring-interpolation

log = logging.getLogger(__name__)
log.setLevel(logging.CRITICAL)

# file system limits
MAX_FILENAME_LENGTH = 255
MAX_PATH_LENGTH = 4096


class Filesystem(ABC):
    """Abstract class representing a filesystem"""

    @abstractmethod
    def is_dir(self, path: str) -> bool:
        """returns True if path is a directory"""

    @abstractmethod
    def mkdir(self, dirpath: str) -> None:
        """creates diretories"""

    @abstractmethod
    def makedirs(self, dirpath: str, exist_ok: bool = False) -> None:
        """creates diretories"""

    @abstractmethod
    def getcwd(self) -> str:
        """returns the current working directory"""

    @abstractmethod
    def chdir(self, directory: str) -> None:
        """changes the current working directory"""

    @abstractmethod
    @contextmanager
    def cwd_cm(self, directory: str) -> None:
        """
        Context manager:
        changes to a directory that is over MAX_PATH_LENGTH
        and then back
        """

    @abstractmethod
    def walk(self, path: str) -> Generator[str, list, list]:
        """
        Generator that returns only regular files and dirs and
        ignores symlinks and other special files
        """

    @abstractmethod
    def open(self, filepath: str, mode: str = "r", encoding=None) -> IO[AnyStr]:
        """opens a file and returns a file descriptor"""

    @abstractmethod
    def get_size(self, filepath: str) -> int:
        """returns the size of a file"""

    @abstractmethod
    def exists(self, filepath: str) -> bool:
        """returns True if filepath exists"""

    @abstractmethod
    def unlink(self, filepath: str) -> None:
        """removes a file"""

    @abstractmethod
    def rmdir(self, dirpath: str) -> None:
        """removes a directory"""

    @abstractmethod
    def rmtree(self, dirpath: str) -> None:
        """removes a directory tree recursively"""


class RealFilesystem(Filesystem):
    """Class representing a real on-disk filesystem"""

    def is_dir(self, path: str):
        """returns True if path is a directory"""
        return safe_is_dir(path)

    def mkdir(self, dirpath: str):
        """creates diretories"""
        name = os.path.basename(dirpath)
        parent = os.path.dirname(dirpath)
        if parent:
            with self.cwd_cm(parent):
                os.mkdir(name)
        else:
            os.mkdir(dirpath)

    def makedirs(self, dirpath: str, exist_ok: bool = False):
        """creates diretories"""
        safe_makedirs(dirpath, exist_ok)

    def getcwd(self):
        """returns the current working directory"""
        return os.getcwd()

    def chdir(self, directory: str):
        """changes the current working directory"""
        safe_chdir(directory)

    @contextmanager
    def cwd_cm(self, directory: str):
        """
        Context manager:
        changes to a directory that is over MAX_PATH_LENGTH
        and then back
        """

        if len(directory) == 0:
            # if directory is empty as a result of path parsing, do nothing
            yield
            return
        try:
            old_cwd = self.getcwd()
        except FileNotFoundError:
            # sometimes we are in a directory that no longer exists ;)
            log.warning("Current working directory no longer exists, will return to /")
            old_cwd = "/"
        try:
            self.chdir(directory)
            yield
        finally:
            self.chdir(old_cwd)

    def walk(self, path: str):
        """
        Generator that returns only regular files and dirs and
        ignores symlinks and other special files
        """
        if not self.is_dir(path):
            raise IOError(f"Directory {path} does not exist or is not a directory")
        with self.cwd_cm(path):
            for root, dirs, files in os.walk("."):
                root = path
                filtered_dirs = []
                filtered_files = []
                for dname in dirs:
                    if os.path.islink(dname):
                        log.warning(
                            f"Symbolic link {os.path.join(path, dname)} ignored."
                        )
                        continue
                    filtered_dirs.append(dname)
                for fname in files:
                    if os.path.islink(fname):
                        log.warning(
                            f"Symbolic link {os.path.join(path, fname)} ignored."
                        )
                        continue
                    if not os.path.isfile(fname):
                        log.warning(
                            f"Special file {os.path.join(path, fname)} ignored."
                        )
                        continue
                    filtered_files.append(fname)
                yield (root, filtered_dirs, filtered_files)

    def open(self, filepath: str, mode: str = "r", encoding=None):
        """opens a file and returns a file descriptor"""
        directory = os.path.dirname(filepath)
        fname = os.path.basename(filepath)
        with self.cwd_cm(directory):
            return open(fname, mode, encoding=encoding)

    def get_size(self, filepath: str):
        """returns the size of a file"""
        fname = os.path.basename(filepath)
        with self.cwd_cm(os.path.dirname(filepath)):
            return os.path.getsize(fname)

    def exists(self, filepath: str):
        """returns True if filepath exists"""
        # TODO: make this max path length safe + tests
        return os.path.exists(filepath)

    def unlink(self, filepath: str):
        """removes a file"""
        # TODO: make this max path length safe + tests
        return os.unlink(filepath)

    def rmdir(self, dirpath: str):
        """removes a directory"""
        return os.rmdir(dirpath)

    def rmtree(self, dirpath: str):
        """removes a directory tree recursively"""
        return shutil.rmtree(dirpath)


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
    safe_chdir(old_cwd)


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


def safe_chdir(directory: str):
    """Changes to a directory that is over MAX_PATH_LENGTH"""
    if len(directory) > MAX_PATH_LENGTH:
        segments = get_safe_path_segments(directory)
        for segment in segments:
            os.chdir(segment)
        if not os.getcwd() == directory:
            raise RuntimeError(
                f"Failed to change to directory {directory}, cwd is "
                f"{os.getcwd()}, segments: {segments}"
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
        safe_chdir(directory)
        yield
    finally:
        safe_chdir(old_cwd)


def safe_walker(directory: str):
    """
    Generator that returns only regular files and dirs and
    ignores symlinks and other special files
    """
    if not safe_is_dir(directory):
        raise IOError(f"Directory {directory} does not exist or is not a directory")
    with safe_cwd_cm(directory):
        for root, dirs, files in os.walk("."):
            root = directory
            filtered_dirs = []
            filtered_files = []
            for dname in dirs:
                if os.path.islink(dname):
                    log.warning(
                        f"Symbolic link {os.path.join(directory, dname)} ignored."
                    )
                    continue
                filtered_dirs.append(dname)
            for fname in files:
                if os.path.islink(fname):
                    log.warning(
                        f"Symbolic link {os.path.join(directory, fname)} ignored."
                    )
                    continue
                if not os.path.isfile(fname):
                    log.warning(
                        f"Special file {os.path.join(directory, fname)} ignored."
                    )
                    continue
                filtered_files.append(fname)
            yield (root, filtered_dirs, filtered_files)


Filesystem.register(RealFilesystem)
