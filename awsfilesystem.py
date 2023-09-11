""" AWS Filesystem module """
import os
import io
from tempfile import mkstemp
from typing import Iterator, BinaryIO
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

# pylint: disable=logging-fstring-interpolation


class S3WriteProxy(io.BytesIO):
    """
    Proxy class for S3 writes.
    Caches all writes to a local file and only writes to S3 when the file is closed.
    This is to ensure we have all the data before uploading so that we can decide
    whether all required data has been uploaded and we can create the final s3 object.
    Otherwise partial uploads would be created as new objects without the user knowing.
    """

    def __init__(self, s3fs_instance, filepath, temp_path="/tmp"):
        self.s3fs = s3fs_instance
        self.s3path = filepath
        self.local_file = None
        self.temp_path = temp_path
        self.fd = None  # pylint: disable=invalid-name
        self._init_local_storage()

    def _init_local_storage(self):
        """initializes local storage"""
        if self.fd is None:
            _, self.local_file = mkstemp(prefix="s3writeproxy-", dir=self.temp_path)
            os.close(_)
            self.fd = open(self.local_file, "wb")

    def close(self, abort=False):
        """
        closes the local temporary file and uploads it to S3.
        Keep in mind that if you interrupt this process S3 will contain
        partially uploaded object that's not visible in normal object
        list and you will still be charged for it.
        See abort_multipart_upload S3 API call for more.
        """
        if self.fd is None:
            return
        self.fd.close()
        if not abort:
            log.info(f"Uploading {self.local_file} to {self.s3path}...")
            self.s3fs.put_file(self.local_file, self.s3path)
            log.info(f"Upload of {self.local_file} to {self.s3path} done.")
        else:
            log.error(f"Aborting upload of {self.local_file} to {self.s3path}...")
        os.remove(self.local_file)
        self.fd = None

    def __enter__(self):
        return self.fd

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            log.debug(
                f"Exception occured, aborting upload to S3. {exc_type} {exc_value} {str(traceback)}"
            )
            self.close(abort=True)
        else:
            self.close()
        return True


class AWSFilesystem(Filesystem):
    """
    S3 Filesystem based on s3fs
    https://s3fs.readthedocs.io/en/latest/api.html
    """

    def __init__(self, bucket, profile):
        self.bucket = bucket
        self.s3fs = s3fs.S3FileSystem(profile=profile)
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
        path_obj = Path(path)
        if path_obj.is_absolute():
            return str(path_obj)
        else:
            return os.path.join(self.cwd, path_obj)

    def abs_s3_path(self, path: str) -> str:
        """
        returns the absolute path of a given path including the bucket name
        """
        path = self.abs_path(path)
        return self.bucket + path

    def is_dir(self, path: str) -> bool:
        """
        returns True if path is not a file in S3.
        S3 does not have directories as such and "directories" are
        made up on the fly from the object names.
        """
        if path == "/":
            return True
        fullpath = self.abs_s3_path(path)
        try:
            info = self.s3fs.info(fullpath)
            if info["type"] == "file":
                return False
            return True
        except FileNotFoundError:
            return True

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
    def cwd_cm(self, directory: str) -> Iterator[None]:
        """
        Context manager:
        changes to a directory that is over MAX_PATH_LENGTH
        and then back
        """
        old_cwd = self.cwd
        self.chdir(directory)
        yield
        self.chdir(old_cwd)

    def walk(self, path: str) -> Iterator[tuple[str, list, list]]:
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

    def open(self, filepath: str, mode: str = "r", encoding=None) -> BinaryIO:
        """opens a file and returns a file descriptor"""
        if len(self.abs_path(filepath)) - 1 > AWS_MAX_OBJECT_NAME_LENGTH:
            raise OSError(
                f"Path too long (max {AWS_MAX_OBJECT_NAME_LENGTH}): {filepath}"
            )
        # we require only read or write mode
        # for write mode we return a proxy object to ensure that
        # partial uploads are not presented as complete files
        if "r" in mode and "w" in mode:
            raise ValueError("Cannot open file in read/write mode")
        if "r" in mode:
            return self.s3fs.open(
                self.abs_s3_path(filepath), mode=mode, encoding=encoding
            )
        elif "w" in mode:
            proxy = S3WriteProxy(self.s3fs, self.abs_s3_path(filepath))
            return proxy
        else:
            raise ValueError("Mode must contain r or w.")

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
