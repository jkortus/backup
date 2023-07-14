""" Module for filesystems interactions"""
from __future__ import annotations
import os
import pathlib
import logging
import shutil
from contextlib import contextmanager
from abc import ABC, abstractmethod
from typing import Generator, IO, AnyStr, Self
from io import BytesIO


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


class VirtualDirectory:
    """Virtual directory"""

    def __init__(self, name: str):
        self.name = name
        self.dirs = []
        self.files = []

    def add_dir(self, name: str):
        """adds a directory"""
        if name in [d.name for d in self.dirs] or name in [f.name for f in self.files]:
            raise IOError(f"Directory or file {name} already exists")
        self.dirs.append(VirtualDirectory(name))

    def del_dir(self, name: str):
        """deletes a directory"""

        for _dir in self.dirs:
            if _dir.name == name:
                self.dirs.remove(_dir)
                return
        raise IOError(f"Directory {name} does not exist")

    def get_dir(self, name: str) -> Self:
        """gets a directory"""
        for _dir in self.dirs:
            if _dir.name == name:
                return _dir
        raise IOError(f"Directory {name} does not exist")

    def add_file(self, file: VirtualFile):
        """adds a file"""
        if file.name in [f.name for f in self.files] or file.name in [
            d.name for d in self.dirs
        ]:
            raise IOError(f"File or directory {file.name} already exists")
        self.files.append(file)

    def get_file(self, name: str) -> VirtualFile:
        """gets a file"""
        for file in self.files:
            if file.name == name:
                return file
        raise IOError(f"File {name} does not exist")

    def del_file(self, name: str):
        """deletes a file"""
        for file in self.files:
            if file.name == name:
                self.files.remove(file)
                return
        raise IOError(f"File {name} does not exist")


class VirtualFileHandle(BytesIO):
    """
    Virtual file handle for binary files.
    Tightly linked to a VirtualFile object and ensures that we don't
    lose data when the handle is closed (default BytesIO behaviour).
    """

    def __init__(self, file: VirtualFile):
        self.file = file
        if file.is_open:
            raise IOError("File is already open. Concurent access is not supported")
        self.file.is_open = True
        self.file._open_handle = self
        super().__init__(self.file.content)

    def close(self):
        """closes the file handle"""
        self.file.content = self.getvalue()
        self.file.is_open = False
        self.file._open_handle = None
        super().close()


class VirtualFile:
    """Virtual file"""

    def __init__(self, name: str):
        self.name = name
        self.content = b""
        self.is_open = False
        self._open_handle = None

    def open(self, mode: str = "r", encoding=None) -> IO[AnyStr]:
        """opens a file, binary only modes are supported ATM"""
        if "b" not in mode:
            raise NotImplementedError("Only binary mode is supported")
        if "r" in mode:
            return VirtualFileHandle(self)
        elif "w" in mode:
            self.content = b""
            return VirtualFileHandle(self)
        elif "a" in mode:
            return VirtualFileHandle(self)
        else:
            raise ValueError(f"Invalid mode {mode}")

    def get_size(self) -> int:
        """returns the size of a file"""
        if self._open_handle is not None:
            return len(self._open_handle.getvalue())
        return len(self.content)


class VirtualFilesystem(Filesystem):
    """Virtual in-memory filesystem"""

    def __init__(self):
        self._cwd = "/"  # keep this absolute
        self.root = VirtualDirectory("/")

    @property
    def cwd(self) -> str:
        """returns the current working directory"""
        return self._cwd

    @cwd.setter
    def cwd(self, path: str) -> None:
        """sets the current working directory, aka chdir"""
        _path = self._abs_path(path)
        if not self.is_dir(_path):
            raise IOError(f"Directory {path} does not exist")
        self._cwd = _path

    def chdir(self, directory: str) -> None:
        """changes the current working directory"""
        self.cwd = directory

    def _get_dir_object(self, path: str) -> VirtualDirectory:
        """returns a VirtualDirectory object for a given path"""
        _path = self._abs_path(path)
        if _path == "/":
            return self.root
        path_obj = pathlib.PurePath(_path)
        cur_dir = self.root
        try:
            for part in path_obj.parts[1:]:
                cur_dir = cur_dir.get_dir(part)
        except IOError as ex:
            raise IOError(f"Directory {path} does not exist") from ex
        return cur_dir

    def get_object(self, path: str) -> VirtualDirectory | VirtualFile:
        """returns a VirtualDirectory or VirtualFile object for a given path"""
        _path = self._abs_path(path)
        if _path == "/":
            return self.root
        name, parent = os.path.basename(_path), os.path.dirname(_path)
        if not parent:
            parent = self.cwd
        parent_dir = self._get_dir_object(parent)
        try:
            return parent_dir.get_dir(name)
        except IOError:
            try:
                return parent_dir.get_file(name)
            except IOError as ex:
                raise IOError(f"Object {path} does not exist") from ex

    def _abs_path(self, path: str) -> str:
        """returns absolute path for any path"""
        if path == ".":
            return self.cwd  # cwd is guaranteed to be absolute
        _path = pathlib.PurePath(path)
        if not _path.is_absolute():
            _path = pathlib.PurePath(self.cwd, path)
        return str(_path)

    def is_dir(self, path: str) -> bool:
        """returns True if path is a directory"""
        _path = self._abs_path(path)
        try:
            self._get_dir_object(_path)
        except IOError:
            return False
        return True

    def mkdir(self, dirpath: str) -> None:
        """creates diretories"""
        name = os.path.basename(dirpath)
        parent = os.path.dirname(dirpath)
        if not parent:
            parent = self.cwd
        parent_dir = self._get_dir_object(parent)
        parent_dir.add_dir(name)

    def makedirs(self, dirpath: str, exist_ok: bool = False) -> None:
        """creates diretories"""
        parent = os.path.dirname(dirpath)
        if not parent:
            parent = self.cwd
        combined_path = ""
        for part in pathlib.PurePath(parent).parts[1:]:
            combined_path = os.path.join(combined_path, part)
            if not self.is_dir(combined_path):
                self.mkdir(combined_path)
        self.mkdir(dirpath)

    def getcwd(self) -> str:
        """returns the current working directory"""
        return self.cwd

    @contextmanager
    def cwd_cm(self, directory: str) -> None:
        """
        Context manager:
        changes to a directory that is over MAX_PATH_LENGTH
        and then back
        """
        old_cwd = self.cwd
        self.cwd = directory
        yield
        self.cwd = old_cwd

    def walk(self, path: str) -> Generator[str, list, list]:
        """returns the next directory content triplet as os.walk() would"""
        global_queue = [path]  # str paths
        while len(global_queue) > 0:
            path = global_queue.pop(0)
            dir_obj = self.get_object(path)
            dirs = [d.name for d in dir_obj.dirs]
            files = [f.name for f in dir_obj.files]
            yield (path, dirs, files)
            global_queue.extend([os.path.join(path, d) for d in dirs])

    def open(self, filepath: str, mode: str = "r", encoding=None) -> IO[AnyStr]:
        """opens a file and returns a file descriptor"""
        non_existent = False
        if not self.exists(filepath):
            non_existent = True
            if not ("w" in mode or "a" in mode):
                raise IOError(f"File {filepath} does not exist")
        name, parent = os.path.basename(filepath), os.path.dirname(filepath)
        if not parent:
            parent = self.cwd
        parent_dir = self._get_dir_object(parent)
        if non_existent:
            parent_dir.add_file(VirtualFile(name))
        file = parent_dir.get_file(name)
        return file.open(mode=mode, encoding=encoding)

    def get_size(self, filepath: str) -> int:
        """returns the size of a file"""
        name, parent = os.path.basename(filepath), os.path.dirname(filepath)
        if not parent:
            parent = self.cwd
        parent_dir = self._get_dir_object(parent)
        file = parent_dir.get_file(name)
        return file.get_size()

    def exists(self, filepath: str) -> bool:
        """returns True if filepath exists"""
        name, parent = os.path.basename(filepath), os.path.dirname(filepath)
        if not parent:
            parent = self.cwd
        try:
            parent_dir = self._get_dir_object(parent)
            file = parent_dir.get_file(name)
            return True
        except IOError:
            return False

    def unlink(self, filepath: str) -> None:
        """removes a file"""
        name, parent = os.path.basename(filepath), os.path.dirname(filepath)
        if not parent:
            parent = self.cwd
        parent_dir = self._get_dir_object(parent)
        parent_dir.del_file(name)

    def rmdir(self, dirpath: str) -> None:
        """removes a directory"""
        if not self.is_dir(dirpath):
            raise IOError(f"Directory {dirpath} does not exist")
        name, parent = os.path.basename(dirpath), os.path.dirname(dirpath)
        dir_obj = self.get_object(dirpath)
        if not parent:
            parent = self.cwd
        parent_dir = self._get_dir_object(parent)
        if dir_obj.files or dir_obj.dirs:
            raise IOError(f"Directory {dirpath} is not empty")
        parent_dir.del_dir(name)

    def rmtree(self, dirpath: str) -> None:
        """removes a directory tree recursively"""
        if not self.is_dir(dirpath):
            raise IOError(f"Directory {dirpath} does not exist")
        dir_obj = self.get_object(dirpath)
        for file in [_.name for _ in dir_obj.files]:
            self.unlink(os.path.join(dirpath, file))
        for subdir in [_.name for _ in dir_obj.dirs]:
            self.rmtree(os.path.join(dirpath, subdir))
        self.rmdir(dirpath)


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
