import os
import subprocess

DEFAULT_TIMEOUT = 60


def run(
    args: list[str], timeout: int = DEFAULT_TIMEOUT, new_session: bool = False
) -> subprocess.CompletedProcess:
    """Run a command and capture its output.

    Callers are expected to catch ``OSError``, ``subprocess.CalledProcessError``
    and ``subprocess.TimeoutExpired`` and turn them into domain-specific errors.

    ``new_session`` starts the command in its own session on POSIX so that
    Ctrl+C is not delivered to daemons it spawns (e.g. wireguard-go).
    """
    kwargs: dict = {}
    if new_session and os.name == "posix":
        kwargs["start_new_session"] = True

    return subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        **kwargs,
    )


def describe_error(exc: BaseException) -> str:
    """Turn a subprocess exception into a message safe to log (no command args)."""
    if isinstance(exc, FileNotFoundError):
        return f"executable not found: {exc.filename or exc}"
    if isinstance(exc, subprocess.TimeoutExpired):
        return f"timed out after {exc.timeout} seconds"
    if isinstance(exc, subprocess.CalledProcessError):
        detail = (exc.stderr or exc.stdout or "").strip()
        message = f"exit code {exc.returncode}"
        return f"{message}: {detail}" if detail else message
    return str(exc)
