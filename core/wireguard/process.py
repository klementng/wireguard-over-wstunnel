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

    def _runtime_name_path(self, iface_name: str) -> str:
        return os.path.join(WIREGUARD_RUN_DIR, f"{iface_name}.name")

    def _read_runtime_interface(self, iface_name: str) -> str:
        """macOS wg-quick creates a utunN device and records its name here."""
        try:
            with open(self._runtime_name_path(iface_name), encoding="utf-8") as file:
                return file.read().strip()
        except OSError:
            return ""

    def _resolve_interface(self, iface_name: str) -> str | None:
        """Return the live device name for a configured interface, if any."""
        interfaces = psutil.net_if_addrs()

        if platform.system() == "Darwin":
            runtime_name = self._read_runtime_interface(iface_name)
            if runtime_name and runtime_name in interfaces:
                return runtime_name
            return None

        if iface_name in interfaces:
            return iface_name
        return None

    @property
    def interface_name(self) -> str | None:
        """Return the actual interface name, which differs from the config name on macOS."""
        return self._resolve_interface(self.config.iface_name)

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

    def _remove_runtime_files(self, iface_name: str) -> None:
        """Delete wg-quick runtime files that outlive a dead wireguard-go daemon.

        When wireguard-go is killed (for example by Ctrl+C), macOS keeps the
        ``<iface>.name`` and ``<utun>.sock`` files behind. ``wg-quick down`` then
        refuses to run because the interface no longer exists, so they have to be
        removed manually or every later start reports a leftover tunnel.
        """
        if platform.system() != "Darwin":
            return

        runtime_name = self._read_runtime_interface(iface_name)
        paths = [self._runtime_name_path(iface_name)]
        if runtime_name:
            paths.append(os.path.join(WIREGUARD_RUN_DIR, f"{runtime_name}.sock"))

        for path in paths:
            try:
                os.remove(path)
            except FileNotFoundError:
                continue
            except OSError as e:
                logger.warning("Unable to remove stale file '%s': %s", path, e)
            else:
                logger.debug("Removed stale wireguard runtime file '%s'", path)

    def _force_down(self, iface_name: str, device: str) -> bool:
        """Last-resort teardown for macOS when wg-quick cannot run.

        wireguard-go watches its UAPI socket and shuts down when the file is
        removed, which also releases the utun device.
        """
        if platform.system() != "Darwin":
            return False

        logger.warning(
            "Falling back to removing wireguard runtime files for '%s'", iface_name
        )
        self._remove_runtime_files(iface_name)
        return self._wait_until_removed(device)

    def _down(self, args: list[str], iface_name: str) -> bool:
        device = self._resolve_interface(iface_name)

        try:
            self._log_output(command.run(args, new_session=True))
        except SUBPROCESS_ERRORS as e:
            if self._resolve_interface(iface_name) is None:
                # The daemon is already gone; wg-quick reports it as "not a
                # WireGuard interface". Treat it as a successful teardown.
                logger.debug(
                    "Interface '%s' is already gone, cleaning up leftovers",
                    iface_name,
                )
                self._remove_runtime_files(iface_name)
                return True

            logger.error(
                "Unable to remove interface '%s': %s",
                iface_name,
                command.describe_error(e),
            )
            return device is not None and self._force_down(iface_name, device)

        if device is not None and not self._wait_until_removed(device):
            if self._force_down(iface_name, device):
                return True

            logger.error("Interface '%s' is still present", device)
            return False

        self._remove_runtime_files(iface_name)
        return True

    def reset(self) -> bool:
        """Remove leftover tunnels and stale runtime files from previous runs."""
        ok = True

        for iface_name in self._installed_interfaces():
            device = self._resolve_interface(iface_name)
            if device is None:
                logger.warning(
                    "Removing stale wireguard runtime files for '%s'", iface_name
                )
                self._remove_runtime_files(iface_name)
                continue

            logger.warning(
                "Found unstopped wireguard interface '%s' (%s), removing...",
                iface_name,
                device,
            )
            if not self._down(self.config.exec_down_args_for(iface_name), iface_name):
                ok = False

        return ok

    def start(self) -> None:
        self.reset()
        logger.info("Starting wireguard...")

        try:
            # Run in a separate session: wireguard-go is daemonized but inherits
            # our process group, so Ctrl+C would otherwise kill the tunnel before
            # stop() gets a chance to remove it properly.
            result = command.run(self.config.exec_up_args, new_session=True)
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
            # Ctrl+C may have already killed wireguard-go, so wg-quick can no
            # longer tear the tunnel down; at least remove what it left behind.
            self._remove_runtime_files(self.config.iface_name)
            return

        logger.info("Stopping wireguard (interface: %s)...", current)

        if not self._down(self.config.exec_down_args, self.config.iface_name):
            raise WireguardRuntimeError(
                f"Unable to stop wireguard (interface: '{current}')"
            )

        logger.info("Stopped wireguard!")

    def restart(self) -> None:
        logger.info("Restarting...")
        self.stop()
        self.start()
