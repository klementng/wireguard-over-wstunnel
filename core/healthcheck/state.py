from ..logger import logger
from .process import HealthCheckProcess


class HealthCheckState(HealthCheckProcess):
    def test(self) -> bool:
        wg_is_healthy = self.wireguard.is_running if self.wireguard else False
        wst_is_healthy = self.wstunnel.is_running if self.wstunnel else False

        if not wg_is_healthy:
            logger.critical("Wireguard process is down!")
        if not wst_is_healthy:
            logger.critical("Wstunnel process is down!")

        return wg_is_healthy and wst_is_healthy

