from ast import Pass
import logging
import platform
import subprocess
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass

import requests

from .process import Process
from .wireguard import WireguardProcess
from .wstunnel import WstunnelProcess


@dataclass
class HealthCheckConfig:
    enabled: bool = True
    interval: int = 60
    restart_wstunnel: bool = False
    restart_wireguard: bool = False

    @classmethod
    def init(cls, config_dict):
        return cls(
            enabled=config_dict.get("enabled", True),
            interval=config_dict.get("interval", 10),
            restart_wstunnel=config_dict.get("restart", {}).get("wstunnel", False),
            restart_wireguard=config_dict.get("restart", {}).get("wireguard", False),
        )


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

        self.logger = logging.getLogger(self.__class__.__name__)
        self.process = None

    def get_status(self):
        if self.status_msg:
            return self.status + ":" + self.status_msg
        else:
            return self.status

    def start(self):
        if self.enabled:
            self.process = threading.Timer(self.interval, self._monitor)
            self.logger.debug("Starting health check.")
            self.process.start()

    def stop(self):
        if self.enabled and self.process:
            self.logger.debug("Stopping health check.")
            self.process.cancel()
            self.status = "stopped"

    def _monitor(self):
        status = self.test()
        self.status = "healthy" if status else "unhealthy"

        try:
            self.logger.debug("Performing health check...")
            if not status:
                self.logger.warning("Health check failed.")
                self.handle_failure()
        except Exception as e:
            self.logger.error(f"Error during health check: {e}")
        finally:
            self.process = threading.Timer(self.interval, self._monitor)
            self.process.daemon = True
            self.process.start()

    def handle_failure(self):
        if self.restart_wg and self.wireguard:
            self.logger.info("Restarting Wireguard...")
            self.wireguard.restart()

        if self.restart_wst and self.wstunnel:
            self.logger.info("Restarting WStunnel...")
            self.wstunnel.restart()

    @abstractmethod
    def test(self) -> bool:
        """Perform the specific health check. Return True if healthy, False otherwise."""
        pass


class HealthCheckPing(HealthCheckProcess):
    def __init__(
        self,
        config: HealthCheckConfig,
        wireguard: WireguardProcess,
        wstunnel: WstunnelProcess,
    ):
        super().__init__(config, wireguard, wstunnel)
        self.servers = [self.wstunnel.config.endpoint_ip, "1.1.1.1", "8.8.8.8"]
        self.flag = "-n" if platform.system() == "Windows" else "-c"

    def test(self) -> bool:
        for server in self.servers:
            res = subprocess.call(
                ["ping", self.flag, "1", server], stdout=subprocess.PIPE
            )
            if res == 0:
                self.logger.debug(f"Ping successful to server: {server}")
                return True
        self.logger.warning(f"Failed to ping any server: {self.servers}")
        return False


class HealthCheckState(HealthCheckProcess):
    def test(self) -> bool:
        wg_is_healthy = self.wireguard.is_running if self.wireguard else False
        wst_is_healthy = self.wstunnel.is_running if self.wstunnel else False

        if not wg_is_healthy:
            self.logger.critical("Wireguard process is down!")
        if not wst_is_healthy:
            self.logger.critical("Wstunnel process is down!")

        return wg_is_healthy and wst_is_healthy


class HealthCheckIP(HealthCheckProcess):
    def __init__(
        self,
        config: HealthCheckConfig,
        wireguard: WireguardProcess,
        wstunnel: WstunnelProcess,
    ):
        super().__init__(config, wireguard, wstunnel)
        self.max_retries = 5
        self.start_ip = self.fetch_ip()
        self.runs = 0

    def start(self):
        self.runs = 0

        return super().start()

    def _monitor(self):
        result = self.test()
        self.status = "healthy" if result else "unhealthy"
        self.runs += 1

        try:
            if result or self.runs >= self.max_retries:
                self.process.cancel()
                self.logger.debug(
                    "Stopping IP health check based on result or max retries."
                )
                self.process.cancel()
                self.status = "exited"
            else:
                self.process = threading.Timer(self.interval, self._monitor)
                self.process.daemon = True
                self.process.start()
        except Exception as e:
            self.logger.error(f"Error in IP monitor: {e}")

    def test(self) -> bool:
        new_ip = self.fetch_ip()

        if new_ip is None:
            self.logger.warning(
                "Failed to fetch Public IP. Your traffic may not be tunneled!"
            )
            self.status_msg = "failed"
            return False

        if self.start_ip is None:
            self.status_msg = "unknown"
            self.logger.warning(
                "Unknown Status! Unable to compare old IP with new IP. "
                "Your traffic may not be tunneled!"
            )
            return True

        if self.start_ip == new_ip:
            self.status_msg = "unchanged"
            self.logger.warning(
                f"IP unchanged: {new_ip}. Your traffic may not be tunneled!"
            )
            return False

        self.status_msg = "success"
        self.logger.info(f"Public IP changed to: {new_ip}")
        return True

    def fetch_ip(self) -> str | None:
        try:
            res = requests.get("https://api.ipify.org", timeout=2)
            res.raise_for_status()
            return res.text
        except Exception as e:
            self.logger.debug("Unable to fetch Public IP.")
            self.logger.debug(e)

            return None
