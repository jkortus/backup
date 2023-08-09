""" AWS Filesystem module """
import os
from typing import Generator, IO, AnyStr
from contextlib import contextmanager
import logging
from pathlib import Path
import copy
import s3fs
from filesystems import Filesystem


logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.ERROR)

AWS_MAX_OBJECT_NAME_LENGTH = 1024  # all paths must be less than this length
AWS_PROFILE = "rolesanywhere"

# pylint: disable=logging-fstring-interpolation


class AWSFilesystem(Filesystem):
    """
    S3 Filesystem based on s3fs
    https://s3fs.readthedocs.io/en/latest/api.html
    """

    def __init__(self, bucket):
        self.bucket = bucket
        self.s3fs = s3fs.S3FileSystem(profile=AWS_PROFILE)
        self._cwd = "/"

    @property
    def cwd(self) -> str:
        """returns current working directory"""
        return self._cwd

    @cwd.setter
    def cwd(self, path: str) -> None:
        """sets current working directory"""
        path = self.abs_path(path)
        if not self.is_dir(path):
            raise FileNotFoundError(f"Directory does not exist: {path}")
        self._cwd = path

    def abs_path(self, path: str) -> str:
        """
        returns the absolute path of a given path including the bucket name
        """
        if path == ".":
            return self.cwd
        path = Path(path)
        if path.is_absolute():
            return str(path)
        else:
            return os.path.join(self.cwd, path)

    def abs_s3_path(self, path: str) -> str:
        """
        returns the absolute path of a given path including the bucket name
        """
        path = self.abs_path(path)
        return self.bucket + path

    def is_dir(self, path: str) -> bool:
        """returns True if path is a directory"""
        if path == "/":
            return True
        fullpath = self.abs_s3_path(path)
        try:
            info = self.s3fs.info(fullpath)
            return info["type"] == "directory"
        except FileNotFoundError:
            return False

    def mkdir(self, dirpath: str) -> None:
        """
        creates diretories
        Warning: in case the directory does not contain any files later
                 it might not be created in s3 at all!
                 This is as expected by the s3fs module.
        """
        if len(self.abs_path(dirpath)) > AWS_MAX_OBJECT_NAME_LENGTH:
            # no -1 in above as the directory gets an extra added / at the end
            raise OSError(
                f"Path too long (max {AWS_MAX_OBJECT_NAME_LENGTH}): {dirpath}"
            )
        self.s3fs.mkdir(self.abs_s3_path(dirpath))

    def makedirs(self, dirpath: str, exist_ok: bool = False) -> None:
        """creates diretories"""
        if len(self.abs_path(dirpath)) > AWS_MAX_OBJECT_NAME_LENGTH:
            # no -1 in above as the directory gets an extra added / at the end
            raise OSError(
                f"Path too long (max {AWS_MAX_OBJECT_NAME_LENGTH}): {dirpath}"
            )
        abs_path = self.abs_path(dirpath)
        if abs_path == "/":
            return
        self.s3fs.mkdirs(self.abs_s3_path(dirpath), exist_ok=exist_ok)

    def getcwd(self) -> str:
        """returns the current working directory"""
        return self.cwd

    def chdir(self, directory: str) -> None:
        """changes the current working directory"""
        self.cwd = directory  # setter will make this absolute

    @contextmanager
    def cwd_cm(self, directory: str) -> None:
        """
        Context manager:
        changes to a directory that is over MAX_PATH_LENGTH
        and then back
        """
        old_cwd = self.cwd
        self.chdir(directory)
        yield
        self.chdir(old_cwd)

    def walk(self, path: str) -> Generator[str, list, list]:
        """
        Generator that returns only regular files and dirs and
        ignores symlinks and other special files
        """
        queue = [path]
        while len(queue) > 0:
            path = queue.pop(0)
            dirs = []
            files = []
            # we need to copy the objects as we're going to modify the structure
            # below. Without this copy internal s3fs cache will be modified and
            # cause random trouble later on
            objects = copy.deepcopy(self.s3fs.ls(self.abs_s3_path(path), detail=True))
            remove_part = self.abs_s3_path(path)
            if not remove_part.endswith("/"):
                remove_part += "/"

            for item in objects:
                # remove aws bucket name and current path from items' names
                item["name"] = item["name"].replace(remove_part, "")

            for item in objects:
                if item["type"] == "directory":
                    dirs.append(item["name"])
                elif item["type"] == "file":
                    files.append(item["name"])
            yield path, dirs, files
            queue.extend([os.path.join(path, d) for d in dirs])

    def open(self, filepath: str, mode: str = "r", encoding=None) -> IO[AnyStr]:
        """opens a file and returns a file descriptor"""
        if len(self.abs_path(filepath)) - 1 > AWS_MAX_OBJECT_NAME_LENGTH:
            raise OSError(
                f"Path too long (max {AWS_MAX_OBJECT_NAME_LENGTH}): {filepath}"
            )
        return self.s3fs.open(self.abs_s3_path(filepath), mode=mode, encoding=encoding)

    def get_size(self, filepath: str) -> int:
        """returns the size of a file"""
        info = self.s3fs.info(self.abs_s3_path(filepath))
        return info["size"]

    def exists(self, filepath: str) -> bool:
        """returns True if filepath exists"""
        # s3fs.exists returns true only for files, not directories
        try:
            self.s3fs.info(self.abs_s3_path(filepath))
            return True
        except FileNotFoundError:
            return False

    def unlink(self, filepath: str) -> None:
        """removes a file"""
        self.s3fs.rm(self.abs_s3_path(filepath))

    def rmdir(self, dirpath: str) -> None:
        """removes a directory"""
        # s3fs.rmdir silently ignores non-empty directory removal
        empty = self.s3fs.ls(self.abs_s3_path(dirpath)) == []
        if not empty:
            raise OSError(f"Directory not empty: {dirpath}")
        self.s3fs.rm(self.abs_s3_path(dirpath))

    def rmtree(self, dirpath: str) -> None:
        """removes a directory tree recursively"""
        self.s3fs.rm(self.abs_s3_path(dirpath), recursive=True)
