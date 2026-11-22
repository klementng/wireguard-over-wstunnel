import collections
import errno
import platform
import re
import signal
import socket
import subprocess
import threading
import time

from ..exception import WstunnelRuntimeError
from ..logger import logger
from ..process import Process
from .config import WstunnelConfig

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class WstunnelProcess(Process):
    def __init__(self, config: WstunnelConfig) -> None:
        self.config = config

        self.process: subprocess.Popen[str] | None = None
        self.process_logger_thread: threading.Thread | None = None
        self._recent_output: collections.deque[str] = collections.deque(maxlen=20)

    def _logger_process(self) -> None:
        stream = self.process.stdout if self.process else None
        if stream is None:
            return

        for line in stream:
            line = ANSI_ESCAPE.sub("", line).strip()
            if line:
                self._recent_output.append(line)
                logger.info(line)

    def get_status(self) -> str:
        return "running" if self.is_running else "stopped"

    @property
    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def _is_port_in_use(self) -> bool:
        """Best-effort check whether wstunnel already listens on the local port."""
        try:
            family = socket.AF_INET6 if ":" in self.config.listen_ip else socket.AF_INET
            sock_type = (
                socket.SOCK_DGRAM if self.config.proto == "udp" else socket.SOCK_STREAM
            )
            with socket.socket(family, sock_type) as sock:
                sock.bind((self.config.listen_ip, self.config.listen_port))
            return False
        except OSError as e:
            return e.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1))

    def _wait_until_listening(self, timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.is_running:
                return False
            if self._is_port_in_use():
                return True
            time.sleep(0.1)

        # Some platforms/containers hide the socket; fall back to process liveness.
        return self.is_running

    def _prime_tunnel(self) -> None:
        """Send a single UDP packet so wstunnel resolves the server eagerly."""
        if self.config.proto != "udp":
            return

        target_ip = (
            "127.0.0.1" if self.config.listen_ip == "0.0.0.0" else self.config.listen_ip
        )

        for attempt in range(3):
            try:
                family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
                with socket.socket(family, socket.SOCK_DGRAM) as sock:
                    sock.sendto(b"start", (target_ip, self.config.listen_port))
                return
            except OSError as e:
                logger.debug(
                    "Unable to prime wstunnel (attempt %s): %s", attempt + 1, e
                )
                time.sleep(0.5)

    def start(self) -> None:
        if self.is_running:
            logger.debug("wstunnel is already running")
            return

        logger.info("Starting...")
        self._recent_output.clear()

        kw: dict = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "text": True,
            "bufsize": 1,
        }

        if platform.system() == "Windows":
            kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kw["start_new_session"] = True

        try:
            self.process = subprocess.Popen(self.config.exec_args, **kw)
        except (OSError, ValueError) as e:
            raise WstunnelRuntimeError(f"Unable to launch wstunnel: {e}") from e

        self.process_logger_thread = threading.Thread(
            target=self._logger_process, daemon=True, name="wstunnel-logger"
        )
        self.process_logger_thread.start()

        if not self._wait_until_listening():
            if self.process_logger_thread is not None:
                self.process_logger_thread.join(timeout=1)

            returncode = self.process.poll() if self.process else None
            message = f"Unable to start wstunnel (exit code: {returncode})"
            if self._recent_output:
                message = f"{message}: {' | '.join(self._recent_output)}"
            raise WstunnelRuntimeError(message)

        self._prime_tunnel()

        logger.info("Started wstunnel!")

    def stop(self) -> None:
        if self.is_running and self.process is not None:
            logger.info("Stopping...")

            if platform.system() == "Windows":
                logger.debug("Stopping using CTRL_BREAK_EVENT")
                self.process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                logger.debug("Stopping using SIGTERM")
                self.process.terminate()

            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.warning(
                    "Process did not terminate within 10 seconds, killing it"
                )
                self.process.kill()
                self.process.wait()

        if self.process_logger_thread is not None:
            self.process_logger_thread.join(timeout=2)
            self.process_logger_thread = None

        self.process = None
        logger.info("Stopped wstunnel")

    def restart(self) -> None:
        logger.info("Restarting...")
        self.stop()
        time.sleep(1)
        self.start()

