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
        if self.is_dir(dirpath):
            if not exist_ok:
                raise IOError(f"Directory {dirpath} already exists")
            return
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
            fnames = [f.name for f in parent_dir.files]
            dnames = [d.name for d in parent_dir.dirs]
            return name in fnames or name in dnames
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
        parent = os.path.dirname(path)
        name = os.path.basename(path)
        if not parent:
            parent = self.getcwd()
        with self.cwd_cm(parent):
            return os.path.isdir(name)

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
        path = pathlib.Path(dirpath)
        root = str(path.parent)
        directory = str(path.name)
        if len(path.parts) < 2:
            raise ValueError(f"Invalid path: {dirpath}")
        with self.cwd_cm("."):  # to return back as we chdir below
            if len(dirpath) > MAX_PATH_LENGTH:
                segments = self.get_safe_path_segments(root)
                for segment in segments:
                    os.makedirs(segment, exist_ok=exist_ok)
                    os.chdir(segment)
                os.makedirs(directory, exist_ok=exist_ok)
            else:
                os.makedirs(dirpath, exist_ok=exist_ok)

    def getcwd(self):
        """returns the current working directory"""
        return os.getcwd()

    def chdir(self, directory: str):
        """changes the current working directory"""
        if len(directory) > MAX_PATH_LENGTH:
            segments = self.get_safe_path_segments(directory)
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
            try:
                self.chdir(old_cwd)
            except FileNotFoundError:
                log.warning("Previous working directory got deleted, returning to /!")
                self.chdir("/")

    def walk(self, path: str):
        """
        Generator that returns only regular files and dirs and
        ignores symlinks and other special files
        """
        if not self.is_dir(path):
            raise IOError(f"Directory {path} does not exist or is not a directory")

        global_queue = [path]  # str paths
        while len(global_queue) > 0:
            path = global_queue.pop(0)
            with self.cwd_cm(path):
                dir_objs = os.scandir(".")
            dirs = []
            files = []
            for obj in dir_objs:
                if obj.is_symlink():
                    log.warning(
                        f"Symbolic link {os.path.join(path, obj.name)} ignored."
                    )
                    continue

                if obj.is_dir():
                    dirs.append(obj.name)
                elif obj.is_file():
                    files.append(obj.name)
                else:
                    # special files end here
                    log.warning(f"Special file {os.path.join(path, obj.name)} ignored.")

            yield (path, dirs, files)
            global_queue.extend([os.path.join(path, d) for d in dirs])

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
        parent = os.path.dirname(filepath)
        if not parent:
            parent = self.getcwd()
        with self.cwd_cm(parent):
            return os.path.exists(os.path.basename(filepath))

    def unlink(self, filepath: str):
        """removes a file"""
        parent = os.path.dirname(filepath)
        if not parent:
            parent = self.getcwd()
        with self.cwd_cm(parent):
            return os.unlink(os.path.basename(filepath))

    def rmdir(self, dirpath: str):
        """removes a directory"""
        parent = os.path.dirname(dirpath)
        if not parent:
            parent = self.getcwd()
        with self.cwd_cm(parent):
            return os.rmdir(os.path.basename(dirpath))

    def rmtree(self, dirpath: str):
        """removes a directory tree recursively"""
        parent = os.path.dirname(dirpath)
        if not parent:
            parent = self.getcwd()
        dirname = os.path.basename(dirpath)
        with self.cwd_cm(parent):
            shutil.rmtree(dirname)

    def get_safe_path_segments(self, path: str) -> list[str]:
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


Filesystem.register(RealFilesystem)
