""" AWS Filesystem module """
import os
from typing import Generator, IO, AnyStr, Self
from contextlib import contextmanager
import logging
import boto3
from filesystems import VirtualFilesystem, VirtualFile, VirtualDirectory


logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


TARGET_BUCKET = (
    "jk-temp-devel-bucket"  # unique across all accounts in aws, use specific names
    # https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
)
DEFAULT_REGION = "us-east-1"
AWS_MAX_OBJECT_NAME_LENGTH = 1024  # all paths must be less than this length


def get_client():
    """returns an AWS client"""
    boto3.setup_default_session(profile_name="rolesanywhere")
    client = boto3.client("sts")
    response = client.get_caller_identity()
    client = boto3.client("s3")
    # log.debug(response)
    return client


class AWSFile(VirtualFile):
    """AWS File"""


class AWSDirectory(VirtualDirectory):
    """AWS Directory"""

    def add_file(self, file: AWSFile):
        """adds a file"""
        return super().add_file(file)

    def get_file(self, name: str) -> AWSFile:
        """gets a file"""
        return super().get_file(name)


class AWSFilesystem(VirtualFilesystem):
    """AWS Filesystem"""

    def __init__(self, client, bucket, region=DEFAULT_REGION):
        super().__init__()
        self.client = client
        self.bucket = bucket
        self.region = region
        self.root = AWSDirectory("/")
        self.dir_class = AWSDirectory
        self.file_class = AWSFile

    def _get_dir_object(self, path: str) -> AWSDirectory:
        """returns a AWS Directory object for a given path"""
        return super()._get_dir_object(path)

    def get_object(self, path: str) -> AWSDirectory | AWSFile:
        """returns a VirtualDirectory or VirtualFile object for a given path"""
        return super().get_object(path)

    def mkdir(self, dirpath: str) -> None:
        """creates diretories"""
        new_abs_path = self._abs_path(dirpath)
        if (
            len(new_abs_path)
            - len(self.root.name)  # root name is not part of the object path in AWS
            + 1  # +1 for an extra "/" at the end for a directory (aws way to identify a directory)
            > AWS_MAX_OBJECT_NAME_LENGTH
        ):
            raise IOError(
                f"Path '{new_abs_path}' too long ({len(new_abs_path)}), max allowed size is {AWS_MAX_OBJECT_NAME_LENGTH} "
            )
        return super().mkdir(dirpath)

    def open(self, filepath: str, mode: str = "r", encoding=None) -> IO[AnyStr]:
        """opens a file and returns a file descriptor"""
        abs_path = self._abs_path(filepath)
        if len(abs_path) > AWS_MAX_OBJECT_NAME_LENGTH:
            raise IOError(
                f"Path '{abs_path}' too long ({len(abs_path)}), max allowed size is {AWS_MAX_OBJECT_NAME_LENGTH} "
            )
        return super().open(filepath, mode, encoding)

    def _get_object_list(self):
        """Returns a list of object names from the bucket"""
        log.debug(f"Getting object list from bucket {self.bucket}")
        paginator = self.client.get_paginator("list_objects_v2")
        pages = 1
        response = []
        for partial_response in paginator.paginate(Bucket=self.bucket):
            log.debug(f"object list page: {pages}")
            log.debug(partial_response)
            pages += 1
            response.extend(partial_response["Contents"])
        object_names = [_["Key"] for _ in response]
        log.debug("object_names:  %s", "\n".join(object_names))
        return object_names

    def load(self):
        """Initializes the filesystem from a list of object names in the bucket"""
        object_names = self._get_object_list()
        for object_name in object_names:
            log.debug("Prosessing object: %s", object_name)
            if object_name.endswith("/"):
                self.makedirs(object_name)
            else:
                dirname = os.path.dirname(object_name)
                if dirname:
                    self.makedirs(dirname, exist_ok=True)
                filename = os.path.basename(object_name)
                self._get_dir_object(dirname).add_file(self.file_class(filename))
