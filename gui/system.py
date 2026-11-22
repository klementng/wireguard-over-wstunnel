import ctypes
import os
from pathlib import Path
import platform
import subprocess
import sys

from core.logger import logger


def get_app_dir() -> Path:
    """Return the containing directory of the app (frozen binary or repo root)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _run_as_desktop_user(cmd: list[str]) -> list[str]:
    """Prefix command with sudo -E -u <SUDO_USER> when elevated via sudo on POSIX."""
    sudo_user = os.environ.get("SUDO_USER")
    geteuid = getattr(os, "geteuid", None)
    if sudo_user and geteuid is not None and geteuid() == 0:
        return ["sudo", "-E", "-u", sudo_user, *cmd]
    return cmd


def open_path(path: str | Path) -> bool:
    """Open a file or directory using the OS default handler."""
    target = Path(path).expanduser().resolve()
    if not target.exists():
        logger.warning("Cannot open '%s': path does not exist", target)
        return False

    system = platform.system()
    try:
        if system == "Windows":
            os.startfile(str(target))  # type: ignore[attr-defined]
        elif system == "Darwin":
            subprocess.Popen(
                _run_as_desktop_user(["open", str(target)]),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            subprocess.Popen(
                _run_as_desktop_user(["xdg-open", str(target)]),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except OSError as e:
        logger.error("Unable to open '%s': %s", target, e)
        return False

    return True


def hide_from_taskbar() -> None:
    """Configure the process as a background tray app without Dock/console clutter."""
    system = platform.system()

    if system == "Darwin":
        try:
            import AppKit  # type: ignore[import-not-found]

            ns_app = AppKit.NSApplication.sharedApplication()
            ns_app.setActivationPolicy_(AppKit.NSApplicationActivationPolicyAccessory)
        except Exception as e:
            logger.debug("Unable to set macOS accessory activation policy: %s", e)
    elif system == "Windows":
        try:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            hwnd = kernel32.GetConsoleWindow()
            # Only hide a dedicated console window (not a shared interactive shell).
            process_list = (ctypes.c_uint32 * 2)()
            if hwnd and kernel32.GetConsoleProcessList(process_list, 2) == 1:
                # SW_HIDE = 0
                ctypes.windll.user32.ShowWindow(hwnd, 0)  # type: ignore[attr-defined]
        except Exception as e:
            logger.debug("Unable to hide Windows console window: %s", e)


def _background_command(argv: list[str] | None = None) -> list[str]:
    """Build the command to re-launch this app without detached flags."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    filtered = [arg for arg in raw_args if arg != "--detached"]

    if getattr(sys, "frozen", False):
        return [sys.executable, *filtered]
    return [sys.executable, os.path.abspath(sys.argv[0]), *filtered]


def detach_to_background(argv: list[str] | None = None) -> None:
    """Spawn a detached copy of this process in the background and exit the parent."""
    cmd = _background_command(argv)
    kw: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }

    if platform.system() == "Windows":
        # DETACHED_PROCESS and CREATE_NO_WINDOW are mutually exclusive on Windows.
        kw["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    else:
        kw["start_new_session"] = True

    logger.info("Detaching tray app to run in background...")
    subprocess.Popen(cmd, **kw)
    sys.exit(0)
