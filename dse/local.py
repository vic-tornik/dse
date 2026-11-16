"""Filesystem primitives for publishing verified immutable development capsules."""
import os
from pathlib import Path

from .dcf import InvalidData, digest


def sync_directory(path):
    if os.name == "posix":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write_file(path, data):
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class LocalChunks:
    def __init__(self, directory: Path):
        self.directory = directory

    def get(self, index, size, expected):
        with (self.directory / f"{index:08x}.bin").open("rb") as stream:
            body = stream.read(size + 1)
        if len(body) != size or digest(body) != expected:
            raise InvalidData(f"Ciphertext integrity failure at chunk {index}")
        return body

    def put(self, index, body):
        expected = digest(body)
        write_file(self.directory / f"{index:08x}.bin", body)
        self.get(index, len(body), expected)
        return expected
