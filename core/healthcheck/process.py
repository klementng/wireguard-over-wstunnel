import threading
from abc import abstractmethod

from ..logger import logger
from ..process import Process
from ..wireguard import WireguardProcess
from ..wstunnel import WstunnelProcess
from .config import HealthCheckConfig


class HealthCheckProcess(Process):
    def __init__(
        self,
        config: HealthCheckConfig,
        wireguard: WireguardProcess,
        wstunnel: WstunnelProcess,
    ):
        self.wireguard = wireguard
        self.wstunnel = wstunnel

        self.enabled = config.enabled
        self.interval = config.interval

        self.restart_wg = config.restart_wireguard
        self.restart_wst = config.restart_wstunnel

        self.status = "not started" if self.enabled else "disabled"
        self.status_msg = ""

        self.process: threading.Timer | None = None
        self._stop_event = threading.Event()
        self._failures = 0

    def get_status(self) -> str:
        if self.status_msg:
            return self.status + ":" + self.status_msg
        return self.status

    def start(self) -> None:
        if not self.enabled:
            return

        self._stop_event.clear()
        self._failures = 0
        self.status = "not started"
        self.status_msg = ""
        logger.debug("Starting health check.")
        self._schedule()

    def stop(self) -> None:
        if not self.enabled:
            return

        logger.debug("Stopping health check.")
        self._stop_event.set()
        if self.process is not None:
            self.process.cancel()
            self.process = None
        self.status = "stopped"

    def _retry_delay(self) -> float:
        """Back off after consecutive failures to avoid restart storms."""
        if not self._failures:
            return self.interval
        # The cap must never make retries faster than the configured interval.
        cap = max(self.interval, 300)
        return min(self.interval * (2 ** min(self._failures, 4)), cap)

    def _schedule(self) -> None:
        if self._stop_event.is_set():
            return

        delay = self._retry_delay()
        if delay != self.interval:
            logger.debug("Next health check in %.0f seconds", delay)

        self.process = threading.Timer(delay, self._monitor)
        self.process.daemon = True
        self.process.start()

    def _monitor(self) -> None:
        if self._stop_event.is_set():
            return

        try:
            status = self.test()
            self.status = "healthy" if status else "unhealthy"

            if status:
                self._failures = 0
            elif not self._stop_event.is_set():
                self._failures += 1
                logger.warning("Health check failed.")
                self.handle_failure()
        except Exception:
            logger.exception("Error during health check")
            self.status = "error"
            self._failures += 1
        finally:
            self._schedule()

    def handle_failure(self) -> None:
        # The transport must be healthy before WireGuard is brought back up.
        if self.restart_wst and self.wstunnel:
            try:
                logger.info("Restarting wstunnel...")
                self.wstunnel.restart()
            except Exception:
                logger.exception("Unable to restart wstunnel")

        if self.restart_wg and self.wireguard:
            try:
                logger.info("Restarting wireguard...")
                self.wireguard.restart()
            except Exception:
                logger.exception("Unable to restart wireguard")

    @abstractmethod
    def test(self) -> bool:
        """Perform the specific health check. Return True if healthy, False otherwise."""
        pass

