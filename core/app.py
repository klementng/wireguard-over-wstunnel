import contextlib
import signal
import threading

from .config import require
from .exception import ConfigError
from .healthcheck import (
    HealthCheckConfig,
    HealthCheckIP,
    HealthCheckPing,
    HealthCheckState,
)
from .logger import logger
from .process import Process
from .wireguard import WireguardConfig, WireguardProcess
from .wstunnel import WstunnelConfig, WstunnelProcess


class Application:
    """Owns the process graph and the run/stop lifecycle."""

    def __init__(self, config: dict):
        self._stop_event = threading.Event()
        self._previous_handlers: dict[int, object] = {}
        self._stopped = False

        health = require(config, "healthcheck")
        if not isinstance(health, dict):
            raise ConfigError("healthcheck must be a mapping")
        health_configs = {
            name: HealthCheckConfig.init(
                require(health, name, "healthcheck"), section=f"healthcheck.{name}"
            )
            for name in ("ping", "state", "ip")
        }
        wst_config = WstunnelConfig.init(require(config, "wstunnel"))
        wg_config = WireguardConfig.init(require(config, "wireguard"), wst_config)

        self.wstunnel = WstunnelProcess(wst_config)
        self.wireguard = WireguardProcess(wg_config)
        self.ip_check = HealthCheckIP(
            health_configs["ip"], self.wireguard, self.wstunnel
        )

        self.processes: list[Process] = [
            self.wstunnel,  # transport first
            self.wireguard,
            HealthCheckPing(health_configs["ping"], self.wireguard, self.wstunnel),
            HealthCheckState(health_configs["state"], self.wireguard, self.wstunnel),
            self.ip_check,
        ]

    def request_stop(self) -> None:
        self._stop_event.set()

    def start(self) -> None:
        self._stopped = False
        started: list[Process] = []

        try:
            self.ip_check.capture_baseline()
            for process in self.processes:
                process.start()
                started.append(process)
        except Exception:
            logger.exception(
                "Unable to start tunnel, stopping all processes",
            )
            self._stop_processes(reversed(started))
            self._stopped = True
            raise

    def stop(self) -> None:
        if self._stopped:
            return

        self._stopped = True
        self._stop_processes(reversed(self.processes))

    def _stop_processes(self, processes) -> None:
        for process in processes:
            try:
                process.stop()
            except Exception as e:
                logger.error("Error stopping %s: %s", process.__class__.__name__, e)

    def _handle_signal(self, signum, _frame) -> None:
        logger.info("Received signal %s, shutting down...", signum)
        self.request_stop()

    def _install_signal_handlers(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self._previous_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._handle_signal)
            except (ValueError, OSError):
                # Not the main thread or the signal is unavailable.
                pass

    def _restore_signal_handlers(self) -> None:
        for sig, handler in self._previous_handlers.items():
            with contextlib.suppress(ValueError, OSError):
                signal.signal(sig, handler)
        self._previous_handlers.clear()

    def run(self) -> None:
        self._install_signal_handlers()
        try:
            self.start()
            logger.info("Tunnel is running. Press Ctrl+C to stop.")
            self._stop_event.wait()
        finally:
            self._restore_signal_handlers()
            self.stop()
            logger.info("Stopped.")


def clean_wireguard(config: dict) -> bool:
    """Remove leftover tunnels without resolving DNS or starting wstunnel."""
    wg_config = WireguardConfig.init(require(config, "wireguard"))
    return WireguardProcess(wg_config).reset()
