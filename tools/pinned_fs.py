"""dir_fd/openat primitives: every component is opened with O_NOFOLLOW beneath a pinned fd.

A path string is never re-resolved after the first open, so a directory swapped for a
symlink between two operations is refused instead of followed.
"""
from __future__ import annotations

import contextlib
import os
import re
import uuid
from pathlib import Path
from typing import Iterable

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW
_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def check_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME.fullmatch(name) or name in {".", ".."} or ".." in name:
        raise ValueError("unsafe path component")
    return name


def open_child(dir_fd: int, name: str, *, create: bool = True, mode: int = 0o700) -> int:
    check_name(name)
    if create:
        with contextlib.suppress(FileExistsError):
            os.mkdir(name, mode, dir_fd=dir_fd)
    try:
        fd = os.open(name, _DIR, dir_fd=dir_fd)
    except OSError as exc:
        raise ValueError("unsafe directory component") from exc
    with contextlib.suppress(OSError):
        os.fchmod(fd, mode)
    return fd


def open_chain(base: str | Path, parts: Iterable[str], *, create: bool = True, mode: int = 0o700) -> int:
    """Open ``base`` (trusted, final component not followed) then each part pinned."""
    try:
        fd = os.open(os.fspath(base), _DIR)
    except OSError as exc:
        raise ValueError("unsafe base directory") from exc
    try:
        for part in parts:
            child = open_child(fd, part, create=create, mode=mode)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_bytes(dir_fd: int, name: str) -> bytes:
    check_name(name)
    try:
        fd = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=dir_fd)
    except OSError as exc:
        raise ValueError("unsafe or missing file") from exc
    with os.fdopen(fd, "rb") as handle:
        return handle.read()


def write_atomic(dir_fd: int, name: str, data: bytes, *, replace: bool = False, mode: int = 0o600) -> bool:
    """Durably write ``name``. Without ``replace`` an existing file wins (returns False)."""
    check_name(name)
    tmp = f".{uuid.uuid4().hex}.tmp"
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | _NOFOLLOW, mode, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            tmp = ""
            created = True
        else:
            try:
                os.link(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
                created = True
            except FileExistsError:
                created = False
        os.fsync(dir_fd)
        return created
    finally:
        if tmp:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp, dir_fd=dir_fd)


def append_bytes(dir_fd: int, name: str, data: bytes, *, mode: int = 0o600) -> None:
    check_name(name)
    fd = os.open(name, os.O_CREAT | os.O_APPEND | os.O_WRONLY | _NOFOLLOW, mode, dir_fd=dir_fd)
    try:
        os.write(fd, data)
        os.fsync(fd)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def list_names(dir_fd: int) -> list[str]:
    return sorted(os.listdir(dir_fd))
