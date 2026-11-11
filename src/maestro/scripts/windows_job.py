"""Own ordinary Windows check descendants before execution; not a sandbox.

The root starts suspended and joins an unnamed, noninheritable job before
resume. No breakaway limits are enabled. See Microsoft's Win32 Job Objects
documentation for child inheritance and kill-on-close semantics.
"""
from __future__ import annotations

import ctypes
import subprocess
import sys
import time
from typing import Any

import psutil

CREATE_SUSPENDED = 0x00000004
_KILL_ON_JOB_CLOSE = 0x00002000
_HANDLE = ctypes.c_void_p
_U32 = ctypes.c_uint32
_I64 = ctypes.c_int64
_SIZE = ctypes.c_size_t


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("process_time", _I64), ("job_time", _I64), ("flags", _U32),
        ("min_working_set", _SIZE), ("max_working_set", _SIZE),
        ("active_process_limit", _U32), ("affinity", _SIZE),
        ("priority_class", _U32), ("scheduling_class", _U32),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ("reads", "writes", "other", "read_bytes", "write_bytes", "other_bytes")]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("basic", _BasicLimits), ("io", _IoCounters),
        ("process_memory", _SIZE), ("job_memory", _SIZE),
        ("peak_process_memory", _SIZE), ("peak_job_memory", _SIZE),
    ]


class _Accounting(ctypes.Structure):
    _fields_ = [
        ("user_time", _I64), ("kernel_time", _I64),
        ("period_user_time", _I64), ("period_kernel_time", _I64),
        ("page_faults", _U32), ("total_processes", _U32),
        ("active_processes", _U32), ("terminated_processes", _U32),
    ]


class WindowsJob:
    def __init__(self) -> None:
        self._api: Any = None
        self._handle: int | None = None
        if sys.platform != "win32":
            raise OSError("Windows job ownership is unavailable on this platform")
        self._api = ctypes.WinDLL("kernel32", use_last_error=True)
        self._api.CreateJobObjectW.argtypes = [_HANDLE, ctypes.c_wchar_p]
        self._api.CreateJobObjectW.restype = _HANDLE
        self._api.SetInformationJobObject.argtypes = [_HANDLE, ctypes.c_int, _HANDLE, _U32]
        self._api.AssignProcessToJobObject.argtypes = [_HANDLE, _HANDLE]
        self._api.TerminateJobObject.argtypes = [_HANDLE, _U32]
        self._api.QueryInformationJobObject.argtypes = [
            _HANDLE, ctypes.c_int, _HANDLE, _U32, ctypes.POINTER(_U32)]
        self._api.CloseHandle.argtypes = [_HANDLE]
        for name in ("SetInformationJobObject", "AssignProcessToJobObject",
                     "TerminateJobObject", "QueryInformationJobObject", "CloseHandle"):
            getattr(self._api, name).restype = ctypes.c_int
        self._handle = self._api.CreateJobObjectW(None, None)
        self._check(bool(self._handle), "CreateJobObject")
        try:
            limits = _ExtendedLimits()
            limits.basic.flags = _KILL_ON_JOB_CLOSE
            self._check(self._api.SetInformationJobObject(
                self._handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)),
                "SetInformationJobObject")
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _check(ok: object, operation: str) -> None:
        if not ok:
            error = getattr(ctypes, "get_last_error", lambda: 0)()
            raise OSError(f"{operation} failed (Windows error {error})")

    def bind_and_resume(self, process: subprocess.Popen) -> None:
        # CPython's original process handle avoids opening a recycled numeric PID.
        native_handle = getattr(process, "_handle", None)
        if native_handle is None:
            raise OSError("check ownership requires the original native process handle")
        self._check(self._api.AssignProcessToJobObject(self._handle, int(native_handle)),
                    "AssignProcessToJobObject")
        try:
            owned = psutil.Process(process.pid)
            if process.poll() is not None:
                raise OSError("owned check exited before resume")
            owned.resume()
        except psutil.Error as exc:
            raise OSError("could not resume the owned check") from exc

    def finish(self) -> None:
        """Terminate and confirm an empty job, including after the root exits."""
        if self._handle is None:
            return
        try:
            self._check(self._api.TerminateJobObject(self._handle, 1), "TerminateJobObject")
            deadline = time.monotonic() + 30
            while True:
                info = _Accounting()
                self._check(self._api.QueryInformationJobObject(
                    self._handle, 1, ctypes.byref(info), ctypes.sizeof(info), None),
                    "QueryInformationJobObject")
                if info.active_processes == 0:
                    return
                if time.monotonic() >= deadline:
                    raise OSError("owned Windows job did not finish cleanup")
                time.sleep(0.01)
        finally:
            self.close()

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            self._check(self._api.CloseHandle(handle), "CloseHandle")
