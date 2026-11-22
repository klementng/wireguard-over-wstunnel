import ctypes
import os
import platform
import shutil
import subprocess
import sys

import psutil

from ..exception import ExecutableNotFoundError
from ..logger import logger


def is_admin() -> bool:
    if platform.system() == "Windows":
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    return os.geteuid() == 0  # type: ignore[attr-defined]


def owns_windows_console() -> bool:
    """Return True if this Windows process has no console or owns a dedicated one.

    A double-clicked Windows executable has either no console, a console hidden by
    PyInstaller (``--hide-console``), or a dedicated console shared only with its
    PyInstaller ``--onefile`` bootloader parent.
    """
    if platform.system() != "Windows":
        return False

    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        hwnd = kernel32.GetConsoleWindow()
        if not hwnd or not user32.IsWindowVisible(hwnd):
            return True

        buf = (ctypes.c_uint32 * 8)()
        count = kernel32.GetConsoleProcessList(buf, len(buf))
        if count == 0:
            return False
        if count == 1:
            return True

        if count == 2 and getattr(sys, "frozen", False):
            pids = {buf[0], buf[1]}
            ppid = os.getppid()
            if pids == {os.getpid(), ppid}:
                parent_exe = psutil.Process(ppid).exe()
                return os.path.normcase(
                    os.path.abspath(parent_exe)
                ) == os.path.normcase(os.path.abspath(sys.executable))

        return False
    except Exception:
        return False


def require_executable(path: str, config_key: str) -> str:
    """Return the resolved path or raise a clear, actionable error."""
    resolved = shutil.which(path)
    if not resolved:
        raise ExecutableNotFoundError(
            f"Executable '{path}' was not found. Install it or set "
            f"'{config_key}' in config.yml."
        )
    return resolved


def _reexec_command() -> list[str]:
    """Command needed to start this program again (frozen binary or script)."""
    if getattr(sys, "frozen", False):
        return [sys.executable, *sys.argv[1:]]

    return [sys.executable, os.path.abspath(sys.argv[0]), *sys.argv[1:]]


def elevate() -> None:
    """Ensure the program is running with administrator/root privileges."""
    system = platform.system()

    if system == "Windows":
        if is_admin():
            return

        logger.info("Elevating to administrator")
        cmd = _reexec_command()
        params = subprocess.list2cmdline(cmd[1:])
        result = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", cmd[0], params, None, 1
        )
        if result <= 32:
            logger.critical("Unable to elevate (ShellExecuteW returned %s)", result)
            sys.exit(1)
        sys.exit(0)

    elif system in ("Linux", "Darwin"):
        if is_admin():
            return

        logger.info("Elevating via sudo")
        try:
            os.execvp("sudo", ["sudo", "-E", *_reexec_command()])
        except OSError as e:
            logger.critical("Unable to elevate via sudo: %s", e)
            sys.exit(1)

    else:
        logger.critical("Unknown/Unsupported OS: %s", system)
        sys.exit(1)
