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


class AWSFile:
    """AWS File"""

    def __init__(self, name: str):
        self.name = name

    def open(self, mode: str = "r", encoding=None) -> IO[AnyStr]:
        """opens a file"""
        raise NotImplementedError

    def get_size(self) -> int:
        """returns size of file"""
        raise NotImplementedError


class AWSDirectory(VirtualDirectory):
    """AWS Directory"""

    def add_file(self, file: AWSFile):
        """adds a file"""
        return super().add_file(file)

    def get_file(self, name: str) -> AWSFile:
        """gets a file"""
        return super().get_file(name)

    def add_dir(self, name: str):
        """adds a directory"""
        return super().add_dir(name)


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


def test():
    client = get_client()
    # list buckets
    paginator = client.get_paginator("list_objects_v2")

    pages = 1
    response = []
    for partial_response in paginator.paginate(Bucket=TARGET_BUCKET):
        print(f"Page: {pages}")
        print(partial_response)
        pages += 1
        response.extend(partial_response["Contents"])

    # for item in response:
    #   print(item["Key"])
