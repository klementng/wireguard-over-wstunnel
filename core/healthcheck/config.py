from dataclasses import dataclass

from ..exception import ConfigError


@dataclass
class HealthCheckConfig:
    enabled: bool = True
    interval: int | float = 60
    restart_wstunnel: bool = False
    restart_wireguard: bool = False

    @classmethod
    def init(cls, config_dict: dict, section: str = "healthcheck") -> "HealthCheckConfig":
        if not isinstance(config_dict, dict):
            raise ConfigError(f"{section} must be a mapping")

        interval = config_dict.get("interval", cls.interval)
        if isinstance(interval, bool) or not isinstance(interval, int | float):
            raise ConfigError(f"{section}.interval must be a number")
        if interval <= 0:
            raise ConfigError(f"{section}.interval must be greater than 0")

        restart = config_dict.get("restart") or {}
        if not isinstance(restart, dict):
            raise ConfigError(f"{section}.restart must be a mapping")

        return cls(
            enabled=config_dict.get("enabled", True),
            interval=interval,
            restart_wstunnel=restart.get("wstunnel", False),
            restart_wireguard=restart.get("wireguard", False),
        )
