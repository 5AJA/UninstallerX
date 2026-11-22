from __future__ import annotations

import ctypes
import subprocess
import time
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Literal


HANDLE = wintypes.HANDLE
DWORD = wintypes.DWORD
PVOID = wintypes.LPVOID
SIZE_T = ctypes.c_size_t
LONG64 = ctypes.c_longlong

JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258


class StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR), ("dwX", DWORD), ("dwY", DWORD), ("dwXSize", DWORD),
        ("dwYSize", DWORD), ("dwXCountChars", DWORD), ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD), ("dwFlags", DWORD), ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD), ("lpReserved2", PVOID),
        ("hStdInput", HANDLE), ("hStdOutput", HANDLE), ("hStdError", HANDLE),
    ]


class StartupInfoEx(ctypes.Structure):
    _fields_ = [("StartupInfo", StartupInfo), ("lpAttributeList", PVOID)]


class ProcessInformation(ctypes.Structure):
    _fields_ = [("hProcess", HANDLE), ("hThread", HANDLE), ("dwProcessId", DWORD), ("dwThreadId", DWORD)]


class BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", LONG64), ("PerJobUserTimeLimit", LONG64), ("LimitFlags", DWORD),
        ("MinimumWorkingSetSize", SIZE_T), ("MaximumWorkingSetSize", SIZE_T),
        ("ActiveProcessLimit", DWORD), ("Affinity", SIZE_T), ("PriorityClass", DWORD), ("SchedulingClass", DWORD),
    ]


class ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", BasicLimitInformation), ("IoInfo", ctypes.c_ulonglong * 6),
        ("ProcessMemoryLimit", SIZE_T), ("JobMemoryLimit", SIZE_T),
        ("PeakProcessMemoryUsed", SIZE_T), ("PeakJobMemoryUsed", SIZE_T),
    ]


class AccountingInformation(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", LONG64), ("TotalKernelTime", LONG64), ("ThisPeriodTotalUserTime", LONG64),
        ("ThisPeriodTotalKernelTime", LONG64), ("TotalPageFaultCount", DWORD), ("TotalProcesses", DWORD),
        ("ActiveProcesses", DWORD), ("TotalTerminatedProcesses", DWORD),
    ]


@dataclass(frozen=True)
class VendorRun:
    exit_code: int | None
    state: Literal["completed", "timed_out", "cancelled", "monitor_failed"] = "completed"
    total_processes: int = 0
    active_processes: int = 0
    reason: str = ""


def _kernel() -> ctypes.WinDLL:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateJobObjectW": (HANDLE, [PVOID, wintypes.LPCWSTR]),
        "SetInformationJobObject": (wintypes.BOOL, [HANDLE, ctypes.c_int, PVOID, DWORD]),
        "QueryInformationJobObject": (wintypes.BOOL, [HANDLE, ctypes.c_int, PVOID, DWORD, ctypes.POINTER(DWORD)]),
        "InitializeProcThreadAttributeList": (wintypes.BOOL, [PVOID, DWORD, DWORD, ctypes.POINTER(SIZE_T)]),
        "UpdateProcThreadAttribute": (wintypes.BOOL, [PVOID, DWORD, SIZE_T, PVOID, SIZE_T, PVOID, PVOID]),
        "DeleteProcThreadAttributeList": (None, [PVOID]),
        "CreateProcessW": (wintypes.BOOL, [wintypes.LPCWSTR, wintypes.LPWSTR, PVOID, PVOID, wintypes.BOOL,
                                           DWORD, PVOID, wintypes.LPCWSTR, ctypes.POINTER(StartupInfoEx),
                                           ctypes.POINTER(ProcessInformation)]),
        "WaitForSingleObject": (DWORD, [HANDLE, DWORD]),
        "GetExitCodeProcess": (wintypes.BOOL, [HANDLE, ctypes.POINTER(DWORD)]),
        "CloseHandle": (wintypes.BOOL, [HANDLE]),
    }
    for name, (restype, argtypes) in signatures.items():
        function = getattr(kernel, name)
        function.restype = restype
        function.argtypes = argtypes
    return kernel


def _launch(kernel: ctypes.WinDLL, job: int, command: tuple[str, ...], cwd: Path, closing: Event) -> ProcessInformation:
    size = SIZE_T()
    kernel.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    if not size.value:
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = ctypes.create_string_buffer(size.value)
    if not kernel.InitializeProcThreadAttributeList(attributes, 1, 0, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    handles = (HANDLE * 1)(job)
    try:
        if not kernel.UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, handles,
                                                ctypes.sizeof(handles), None, None):
            raise ctypes.WinError(ctypes.get_last_error())
        startup = StartupInfoEx()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.lpAttributeList = ctypes.cast(attributes, PVOID)
        process = ProcessInformation()
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
        if not closing.is_set() and not kernel.CreateProcessW(
            command[0], command_line, None, None, False, EXTENDED_STARTUPINFO_PRESENT, None, str(cwd),
            ctypes.byref(startup), ctypes.byref(process),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return process
    finally:
        kernel.DeleteProcThreadAttributeList(attributes)


def run_vendor(command: tuple[str, ...], *, cwd: Path, closing: Event,
               on_event: Callable[..., None], timeout: float = 600) -> VendorRun:
    """Observe the approved command and its Windows job without terminating it."""
    if not command or not Path(command[0]).is_absolute():
        raise ValueError("The uninstaller executable path must be absolute.")
    kernel = _kernel()
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        # Preserve a vendor's ability to explicitly launch outside the job.
        limits = ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK
        if not kernel.SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(limits),
                                              ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())
        process = _launch(kernel, job, command, cwd, closing)
        if not process.hProcess:
            return VendorRun(None, state="cancelled")
        kernel.CloseHandle(process.hThread)
        try:
            return _wait_for_vendor(kernel, job, process, closing, on_event, deadline=time.monotonic() + timeout)
        finally:
            kernel.CloseHandle(process.hProcess)
    finally:
        kernel.CloseHandle(job)


def _wait_for_vendor(kernel: ctypes.WinDLL, job: int, process: ProcessInformation, closing: Event,
                     on_event: Callable[..., None], *, deadline: float) -> VendorRun:
    exit_code = None
    total, active = 1, 1
    accounting = AccountingInformation()
    on_event("uninstaller_started", pid=process.dwProcessId)
    try:
        while True:
            launcher_exited = False
            if exit_code is None:
                state = kernel.WaitForSingleObject(process.hProcess, 0)
                if state == WAIT_OBJECT_0:
                    code = DWORD()
                    if not kernel.GetExitCodeProcess(process.hProcess, ctypes.byref(code)):
                        raise ctypes.WinError(ctypes.get_last_error())
                    exit_code = code.value
                    launcher_exited = True
                    on_event("uninstaller_launcher_exited", pid=process.dwProcessId, exit_code=exit_code)
                elif state != WAIT_TIMEOUT:
                    raise ctypes.WinError(ctypes.get_last_error())
            if not kernel.QueryInformationJobObject(job, JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                                                    ctypes.byref(accounting), ctypes.sizeof(accounting), None):
                raise ctypes.WinError(ctypes.get_last_error())
            total, active = accounting.TotalProcesses, accounting.ActiveProcesses
            if launcher_exited and active and total > 1:
                on_event("uninstaller_waiting_for_children", active_processes=active)
            if exit_code is not None and not active:
                return VendorRun(exit_code, total_processes=total)
            remaining = deadline - time.monotonic()
            if closing.is_set():
                return VendorRun(exit_code, "cancelled", total, active)
            if remaining <= 0:
                return VendorRun(exit_code, "timed_out", total, active)
            closing.wait(min(0.2, remaining))
    except OSError as exc:
        return VendorRun(exit_code, "monitor_failed", total, active, str(exc))
