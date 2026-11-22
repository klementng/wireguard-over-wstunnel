import os
import platform
import subprocess
import time

import psutil

from core.utils import command

from ..exception import WireguardRuntimeError
from ..logger import logger
from ..process import Process
from .config import (
    IFACE_PREFIX,
    WIREGUARD_RUN_DIR,
    WireguardConfig,
)

STOP_TIMEOUT = 15
START_TIMEOUT = 5

SUBPROCESS_ERRORS = (
    subprocess.CalledProcessError,
    subprocess.TimeoutExpired,
    OSError,
)


class WireguardProcess(Process):
    def __init__(self, config: WireguardConfig) -> None:
        self.config = config

    def get_status(self) -> str:
        return "running" if self.is_running else "stopped"

    def _read_runtime_interface(self) -> str:
        """macOS wg-quick creates a utunN device and records its name here."""
        try:
            with open(self.config.runtime_name_file, encoding="utf-8") as file:
                return file.read().strip()
        except OSError:
            return ""

    @property
    def interface_name(self) -> str | None:
        """Return the actual interface name, which differs from the config name on macOS."""
        interfaces = psutil.net_if_addrs()

        if platform.system() == "Darwin":
            runtime_name = self._read_runtime_interface()
            if runtime_name and runtime_name in interfaces:
                return runtime_name

        if self.config.iface_name in interfaces:
            return self.config.iface_name

        return None

    @property
    def is_running(self) -> bool:
        return self.interface_name is not None

    @staticmethod
    def _installed_interfaces() -> list[str]:
        if platform.system() == "Darwin":
            # macOS uses utunN; wg-quick records the mapping in <iface>.name.
            try:
                entries = os.listdir(WIREGUARD_RUN_DIR)
            except OSError:
                return []

            return sorted(
                entry[: -len(".name")]
                for entry in entries
                if entry.startswith(IFACE_PREFIX) and entry.endswith(".name")
            )

        return sorted(
            name for name in psutil.net_if_addrs() if name.startswith(IFACE_PREFIX)
        )

    def _wait_until_running(self, timeout: int = START_TIMEOUT) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.is_running:
                return True
            time.sleep(0.1)
        return False

    def _wait_until_removed(self, iface_name: str, timeout: int = STOP_TIMEOUT) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if iface_name not in psutil.net_if_addrs():
                return True
            time.sleep(0.1)
        return False

    def _log_output(self, result: subprocess.CompletedProcess) -> None:
        output = (result.stderr or "").strip() or (result.stdout or "").strip()
        for line in output.splitlines():
            logger.debug("wg-quick: %s", line)

    def _down(self, args: list[str], iface_name: str) -> bool:
        try:
            self._log_output(command.run(args))
        except SUBPROCESS_ERRORS as e:
            logger.error(
                "Unable to remove interface '%s': %s",
                iface_name,
                command.describe_error(e),
            )
            return False

        if not self._wait_until_removed(iface_name):
            logger.error("Interface '%s' is still present", iface_name)
            return False

        return True

    def reset(self) -> bool:
        """Remove our tunnel and any leftover wg-wst-* interfaces."""
        ok = True
        current = self.interface_name

        if current is not None:
            logger.warning(
                "Found unstopped wireguard tunnel '%s', removing...", current
            )
            ok = self._down(self.config.exec_down_args, current)

        handled = {current} if current else set()
        for iface_name in self._installed_interfaces():
            if iface_name in handled:
                continue

            logger.warning(
                "Found unstopped wireguard interface '%s', removing...", iface_name
            )
            if not self._down(self.config.exec_down_args_for(iface_name), iface_name):
                ok = False

        return ok

    def start(self) -> None:
        self.reset()
        logger.info("Starting wireguard...")

        try:
            result = command.run(self.config.exec_up_args)
            self._log_output(result)
        except SUBPROCESS_ERRORS as e:
            raise WireguardRuntimeError(
                f"Unable to run '{self.config.exec_path}': {command.describe_error(e)}"
            ) from e

        if not self._wait_until_running():
            raise WireguardRuntimeError(
                "WireGuard reported success but no interface appeared. "
                f"Expected '{self.config.iface_name}'. Check the log and "
                f"the generated config at '{self.config.conf_path}'."
            )

        logger.info("Started wireguard! (interface: %s)", self.interface_name)

    def stop(self) -> None:
        current = self.interface_name
        if current is None:
            return

        logger.info("Stopping wireguard (interface: %s)...", current)

        try:
            result = command.run(self.config.exec_down_args)
            self._log_output(result)
        except SUBPROCESS_ERRORS as e:
            raise WireguardRuntimeError(
                f"Unable to stop wireguard: {command.describe_error(e)}"
            ) from e

        if not self._wait_until_removed(current):
            raise WireguardRuntimeError(
                f"Interface '{current}' is still present after stop"
            )

        logger.info("Stopped wireguard!")

    def restart(self) -> None:
        logger.info("Restarting...")
        self.stop()
        self.start()
