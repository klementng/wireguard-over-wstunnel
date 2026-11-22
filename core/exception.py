"""Shared application exceptions."""


class ConfigError(Exception):
    pass


class WireguardError(Exception):
    pass


class WireguardConfigError(WireguardError, ConfigError):
    pass


class WireguardRuntimeError(WireguardError):
    pass


class WstunnelError(Exception):
    pass


class WstunnelConfigError(WstunnelError, ConfigError):
    pass


class WstunnelRuntimeError(WstunnelError):
    pass


class ExecutableNotFoundError(RuntimeError):
    pass
