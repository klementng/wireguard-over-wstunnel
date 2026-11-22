import requests

from ..logger import logger
from ..wireguard import WireguardProcess
from ..wstunnel import WstunnelProcess
from .config import HealthCheckConfig
from .process import HealthCheckProcess


class HealthCheckIP(HealthCheckProcess):
    def __init__(
        self,
        config: HealthCheckConfig,
        wireguard: WireguardProcess,
        wstunnel: WstunnelProcess,
    ):
        super().__init__(config, wireguard, wstunnel)
        self.max_retries = 5
        self.start_ip: str | None = None
        self.runs = 0

    def start(self) -> None:
        if not self.enabled:
            return

        # Baseline the public IP after the tunnel has been started.
        self.start_ip = self.fetch_ip()
        self.runs = 0
        super().start()

    def _monitor(self) -> None:
        if self._stop_event.is_set():
            return

        try:
            result = self.test()
            self.status = "healthy" if result else "unhealthy"
            self.runs += 1

            if result or self.runs >= self.max_retries:
                logger.debug(
                    "Stopping IP health check based on result or max retries."
                )
                self.status = "exited"
        except Exception:
            logger.exception("Error in IP monitor")
            self.status = "error"
            self.runs += 1
        finally:
            if self.runs >= self.max_retries and self.status != "exited":
                self.status = "exited"
            if self.status != "exited":
                self._schedule()

    def test(self) -> bool:
        new_ip = self.fetch_ip()

        if new_ip is None:
            logger.warning(
                "Failed to fetch Public IP. Your traffic may not be tunneled!"
            )
            self.status_msg = "failed"
            return False

        if self.start_ip is None:
            self.status_msg = "unknown"
            logger.warning(
                "Unknown Status! Unable to compare old IP with new IP. "
                "Your traffic may not be tunneled!"
            )
            return True

        if self.start_ip == new_ip:
            self.status_msg = "unchanged"
            logger.warning(
                "IP unchanged: %s. Your traffic may not be tunneled!", new_ip
            )
            return False

        self.status_msg = "success"
        logger.info("Public IP changed to: %s", new_ip)
        return True

    def fetch_ip(self) -> str | None:
        try:
            res = requests.get("https://api.ipify.org", timeout=5)
            res.raise_for_status()
            return res.text.strip()
        except Exception as e:
            logger.debug("Unable to fetch Public IP: %s", e)
            return None
