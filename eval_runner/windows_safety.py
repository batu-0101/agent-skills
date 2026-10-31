"""Native Windows handle-relative no-follow access for the eval sandbox.

Every child is opened relative to an already-held directory handle. Reparse
points are inspected without resolving them. Open handles deny delete sharing,
so a validated directory cannot be renamed or replaced until its children have
been processed. Cleanup deletes the opened entry without changing attributes.
There is deliberately no pathname/rmtree fallback.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
from contextlib import ExitStack, contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import struct
import tempfile

if os.name != 'nt':
    raise ImportError('Windows handle safety is only available on Windows')

K = C.WinDLL('kernel32', use_last_error=True)
N = C.WinDLL('ntdll')
READ = 0x100081  # SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_READ_DATA/LIST_DIRECTORY
REMOVE = READ | 0x10000  # DELETE; no permission to change shared file attributes
REPARSE = 0x400
DIRECTORY = 0x10
INVALID = C.c_void_p(-1).value


class UnicodeString(C.Structure):
    _fields_ = [('Length', W.USHORT), ('MaximumLength', W.USHORT), ('Buffer', W.LPWSTR)]


class ObjectAttributes(C.Structure):
    _fields_ = [('Length', W.ULONG), ('RootDirectory', W.HANDLE),
                ('ObjectName', C.POINTER(UnicodeString)), ('Attributes', W.ULONG),
                ('SecurityDescriptor', W.LPVOID), ('SecurityQualityOfService', W.LPVOID)]


class IoStatus(C.Structure):
    _fields_ = [('Status', C.c_void_p), ('Information', C.c_size_t)]


class AttributeTag(C.Structure):
    _fields_ = [('FileAttributes', W.DWORD), ('ReparseTag', W.DWORD)]


K.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
K.CreateFileW.restype = W.HANDLE
K.CloseHandle.argtypes = [W.HANDLE]
K.CloseHandle.restype = W.BOOL
K.GetFileInformationByHandleEx.argtypes = [W.HANDLE, C.c_int, W.LPVOID, W.DWORD]
K.GetFileInformationByHandleEx.restype = W.BOOL
K.SetFileInformationByHandle.argtypes = [W.HANDLE, C.c_int, W.LPVOID, W.DWORD]
K.SetFileInformationByHandle.restype = W.BOOL
K.ReadFile.argtypes = [W.HANDLE, W.LPVOID, W.DWORD, C.POINTER(W.DWORD), W.LPVOID]
K.ReadFile.restype = W.BOOL
K.GetFileType.argtypes = [W.HANDLE]
K.GetFileType.restype = W.DWORD
N.NtCreateFile.argtypes = [C.POINTER(W.HANDLE), W.DWORD, C.POINTER(ObjectAttributes),
    C.POINTER(IoStatus), W.LPVOID, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.LPVOID, W.DWORD]
N.NtCreateFile.restype = C.c_long
N.NtQueryDirectoryFile.argtypes = [W.HANDLE, W.HANDLE, W.LPVOID, W.LPVOID,
    C.POINTER(IoStatus), W.LPVOID, W.ULONG, C.c_int, C.c_ubyte, W.LPVOID, C.c_ubyte]
N.NtQueryDirectoryFile.restype = C.c_long
N.RtlNtStatusToDosError.argtypes = [C.c_long]
N.RtlNtStatusToDosError.restype = W.ULONG


def _raise_status(status: int) -> None:
    raise C.WinError(N.RtlNtStatusToDosError(status))


def _component(name: str) -> str:
    if (not name or len(name.encode('utf-16-le')) > 510 or name in {'.', '..'} or any(c in name for c in '/\\:')
            or name.endswith((' ', '.')) or any(ord(c) < 32 for c in name)
            or re.fullmatch(r'(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', name, re.I)):
        raise ValueError('unsafe Windows path component: ' + repr(name))
    return name


def _open_root(path: Path, access: int = READ) -> int:
    absolute = os.path.abspath(path)
    extended = ('\\\\?\\UNC\\' + absolute[2:]) if absolute.startswith('\\\\') else '\\\\?\\' + absolute
    handle = K.CreateFileW(extended, access, 3, None, 3, 0x02200000, None)
    if handle == INVALID:
        raise C.WinError(C.get_last_error())
    return handle


def _open_relative(parent: int, name: str, access: int = READ) -> int:
    _component(name)
    buffer = C.create_unicode_buffer(name)
    length = len(name.encode('utf-16-le'))
    string = UnicodeString(length, length + 2, C.cast(buffer, W.LPWSTR))
    attrs = ObjectAttributes(C.sizeof(ObjectAttributes), parent, C.pointer(string), 0x40, None, None)
    result, io = W.HANDLE(), IoStatus()
    # FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT.
    status = N.NtCreateFile(C.byref(result), access, C.byref(attrs), C.byref(io),
        None, 0, 3 if access == REMOVE else 1, 1, 0x00200020, None, 0)
    if status < 0:
        _raise_status(status)
    return result.value


@contextmanager
def _held(handle: int):
    try:
        yield handle
    finally:
        if not K.CloseHandle(handle):
            raise C.WinError(C.get_last_error())


def _attributes(handle: int) -> int:
    data = AttributeTag()
    if not K.GetFileInformationByHandleEx(handle, 9, C.byref(data), C.sizeof(data)):
        raise C.WinError(C.get_last_error())
    return data.FileAttributes


def _require_directory(handle: int) -> None:
    attrs = _attributes(handle)
    if attrs & REPARSE or not attrs & DIRECTORY:
        raise ValueError('unsafe symlink/reparse or non-directory component in contained path')


def hash_contained_file(root: Path, relative_path: str) -> str | None:
    # The caller performs the shared POSIX lexical validation first; Windows
    # also rejects ADS, device aliases and names normalized to another entry.
    parts = PurePosixPath(relative_path).parts
    for name in parts:
        _component(name)
    root_path = root.resolve(strict=True)
    try:
        with ExitStack() as stack:
            parent = stack.enter_context(_held(_open_root(root_path)))
            _require_directory(parent)
            for name in parts[:-1]:
                parent = stack.enter_context(_held(_open_relative(parent, name)))
                _require_directory(parent)
            file = stack.enter_context(_held(_open_relative(parent, parts[-1])))
            attrs = _attributes(file)
            if attrs & REPARSE:
                raise ValueError('unsafe symlink/reparse component in contained path: ' + relative_path)
            if attrs & DIRECTORY or K.GetFileType(file) != 1:
                return None
            digest, buffer, count = hashlib.sha256(), C.create_string_buffer(65536), W.DWORD()
            while True:
                if not K.ReadFile(file, buffer, len(buffer), C.byref(count), None):
                    raise C.WinError(C.get_last_error())
                if not count.value:
                    return digest.hexdigest()[:16]
                digest.update(buffer.raw[:count.value])
    except FileNotFoundError:
        return None


def _names(handle: int):
    buffer, io, restart = C.create_string_buffer(65536), IoStatus(), True
    while True:
        status = N.NtQueryDirectoryFile(handle, None, None, None, C.byref(io),
            buffer, len(buffer), 12, False, None, restart)
        restart = False
        if status & 0xffffffff == 0x80000006:  # STATUS_NO_MORE_FILES
            return
        if status < 0:
            _raise_status(status)
        data, offset = buffer.raw[:io.Information], 0
        while offset < len(data):
            next_offset, _, size = struct.unpack_from('<III', data, offset)
            name = data[offset + 12:offset + 12 + size].decode('utf-16-le')
            if name not in {'.', '..'}:
                yield _component(name)
            if not next_offset:
                break
            offset += next_offset


def _delete_opened(handle: int) -> None:
    attrs = _attributes(handle)
    if attrs & DIRECTORY and not attrs & REPARSE:
        # A one-time race may rename a not-yet-opened child into a new name
        # during enumeration. Rescan the same anchored directory, bounded so
        # a continuously mutating adversary cannot keep cleanup running forever.
        for _attempt in range(8):
            names = list(_names(handle))
            if not names:
                break
            for name in names:
                try:
                    child = _open_relative(handle, name, REMOVE)
                except FileNotFoundError:
                    continue
                with _held(child):
                    _delete_opened(child)
        else:
            if list(_names(handle)):
                raise RuntimeError('Sandbox directory kept changing during bounded native cleanup')
    # FileDispositionInfoEx: DELETE | IGNORE_READONLY_ATTRIBUTE. Never clear
    # attributes: an NTFS hard link may share them with an external file.
    # Unsupported kernels/filesystems fail closed instead of mutating metadata.
    disposition = W.DWORD(0x11)
    if not K.SetFileInformationByHandle(handle, 21, C.byref(disposition), C.sizeof(disposition)):
        raise C.WinError(C.get_last_error())


def cleanup_sandbox(staged_path: Path) -> None:
    target = Path(os.path.abspath(staged_path)).parent
    temp = Path(tempfile.gettempdir()).resolve(strict=True)
    # Only the explicitly-created eval staging roots may be recursively removed.
    # Resolve the parent, never the target (which may have become a junction).
    if target.parent.resolve(strict=True) != temp or not target.name.startswith(('eval-sandbox-', 'eval-baseline-')):
        raise ValueError('cleanup target is not an owned eval staging directory')
    try:
        with _held(_open_root(temp, READ)) as parent:
            _require_directory(parent)
            with _held(_open_relative(parent, target.name, REMOVE)) as handle:
                _delete_opened(handle)
    except FileNotFoundError:
        return
