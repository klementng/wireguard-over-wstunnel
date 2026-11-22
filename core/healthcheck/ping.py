import platform
import subprocess

from ..logger import logger
from ..wireguard import WireguardProcess
from ..wstunnel import WstunnelProcess
from .config import HealthCheckConfig
from .process import HealthCheckProcess


class HealthCheckPing(HealthCheckProcess):
    def __init__(
        self,
        config: HealthCheckConfig,
        wireguard: WireguardProcess,
        wstunnel: WstunnelProcess,
    ):
        super().__init__(config, wireguard, wstunnel)

        servers = [self.wstunnel.config.endpoint_ip, "1.1.1.1", "8.8.8.8"]
        self.servers = list(dict.fromkeys(server for server in servers if server))

        system = platform.system()
        if system == "Windows":
            self.ping_cmd = ["ping", "-n", "1", "-w", "2000"]
        elif system == "Darwin":
            self.ping_cmd = ["ping", "-c", "1", "-W", "2000"]
        else:
            self.ping_cmd = ["ping", "-c", "1", "-W", "2"]

    def test(self) -> bool:
        for server in self.servers:
            try:
                res = subprocess.run(
                    [*self.ping_cmd, server],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
            except (OSError, subprocess.TimeoutExpired) as e:
                logger.debug("Ping to %s failed: %s", server, e)
                continue

            if res.returncode == 0:
                logger.debug("Ping successful to server: %s", server)
                return True

        logger.warning("Failed to ping any server: %s", self.servers)
        return False

