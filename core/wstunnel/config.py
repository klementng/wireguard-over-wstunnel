from dataclasses import dataclass
import ipaddress
import json
import os
import platform
import re
import socket
from urllib.parse import urlsplit, urlunsplit

from core.utils.system import require_executable

from ..exception import ExecutableNotFoundError, WstunnelConfigError
from ..logger import logger

DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
DNS_CACHE_FILE = os.path.join("conf", "dns.json")

TLS_SCHEMES = {"wss", "https", "wts"}
WSS_SCHEMES = {"ws", "wss", "http", "https", "wts"}


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _replace_server_host(server: str, ip: str) -> str:
    """Replace the hostname in a server URL with a resolved IP address."""
    parts = urlsplit(server)
    formatted_ip = f"[{ip}]" if ":" in ip else ip

    userinfo = ""
    if parts.username is not None:
        userinfo = parts.username
        if parts.password is not None:
            userinfo = f"{userinfo}:{parts.password}"
        userinfo = f"{userinfo}@"

    port = f":{parts.port}" if parts.port is not None else ""
    netloc = f"{userinfo}{formatted_ip}{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _has_host_header(args: dict) -> bool:
    for key in ("http-headers", "H"):
        value = args.get(key)
        headers = (
            value
            if isinstance(value, list | tuple)
            else ([value] if isinstance(value, str) else [])
        )
        for header in headers:
            if isinstance(header, str) and header.strip().lower().startswith("host:"):
                return True
    return False


def _append_http_header(args: dict, header: str) -> None:
    existing = args.get("http-headers")
    if existing is None or existing is False:
        args["http-headers"] = [header]
    elif isinstance(existing, list | tuple):
        args["http-headers"] = [*existing, header]
    else:
        args["http-headers"] = [existing, header]


@dataclass
class WstunnelConfig:
    exec_path: str
    exec_args: list[str]
    server: str
    host: str
    endpoint_port: int
    endpoint_ip: str
    proto: str
    listen_ip: str
    listen_port: int
    remote_ip: str
    remote_port: int
    connect_args: str

    @classmethod
    def init(cls, config: dict) -> "WstunnelConfig":
        """Validate settings and build the transport configuration."""
        if not isinstance(config, dict):
            raise WstunnelConfigError("wstunnel must be a mapping")

        paths = config.get("path")
        if not isinstance(paths, dict):
            raise WstunnelConfigError("wstunnel.path must be a mapping")

        args = config.get("args")
        if not isinstance(args, dict):
            raise WstunnelConfigError("wstunnel.args must be a mapping")
        if not args.get("server"):
            raise WstunnelConfigError("wstunnel.args.server is not set")
        if not args.get("local-to-remote"):
            raise WstunnelConfigError("wstunnel.args.local-to-remote is not set")

        plat = platform.system().lower()
        path = paths.get(plat)
        if not path:
            raise WstunnelConfigError(f"Config key 'path.{plat}' is not set")
        try:
            path = require_executable(str(path), f"wstunnel.path.{plat}")
        except ExecutableNotFoundError as e:
            raise WstunnelConfigError(str(e)) from e
        server, host, endpoint_port, endpoint_ip = cls.parse_server_settings(config)
        proto, listen_ip, listen_port, remote_ip, remote_port, connect_args = (
            cls.parse_tunnel_settings(config)
        )
        return cls(
            exec_path=path,
            exec_args=cls.generate_exec_args(
                config, path, host=host, endpoint_ip=endpoint_ip
            ),
            server=server,
            host=host,
            endpoint_port=endpoint_port,
            endpoint_ip=endpoint_ip,
            proto=proto,
            listen_ip=listen_ip,
            listen_port=listen_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
            connect_args=connect_args,
        )

    @staticmethod
    def generate_exec_args(
        config: dict,
        exec_path: str,
        *,
        host: str | None = None,
        endpoint_ip: str | None = None,
    ) -> list[str]:
        args = config.get("args")
        if not isinstance(args, dict):
            raise WstunnelConfigError("Config key 'args' is not set")

        args = dict(args)
        server = args.pop("server", None)
        if not server:
            raise WstunnelConfigError("Config key 'server' is not set")

        server_str = str(server)
        using_proxy = bool(args.get("http-proxy") or args.get("p"))

        # Connect directly to the pre-resolved IP so wstunnel does not rely on
        # OS/tunnel DNS at runtime (which fails on Windows or after WG starts).
        if host and endpoint_ip and not using_proxy and not _is_ip_address(host):
            parts = urlsplit(server_str)
            server_str = _replace_server_host(server_str, endpoint_ip)

            if (
                parts.scheme in TLS_SCHEMES
                and not args.get("tls-sni-override")
                and not args.get("tls-sni-disable")
            ):
                args["tls-sni-override"] = host

            if not args.get("http-headers-file") and not _has_host_header(args):
                default_port = (
                    DEFAULT_HTTPS_PORT
                    if parts.scheme in TLS_SCHEMES
                    else DEFAULT_HTTP_PORT
                )
                host_value = (
                    f"{host}:{parts.port}"
                    if parts.port and parts.port != default_port
                    else host
                )
                _append_http_header(args, f"Host: {host_value}")

        server_str = str(server)
        using_proxy = bool(args.get("http-proxy") or args.get("p"))

        # Connect directly to the pre-resolved IP so wstunnel does not rely on
        # OS/tunnel DNS at runtime (which fails on Windows or after WG starts).
        if (
            host
            and endpoint_ip
            and not using_proxy
            and not _is_ip_address(host)
        ):
            parts = urlsplit(server_str)
            server_str = _replace_server_host(server_str, endpoint_ip)

            if (
                parts.scheme in TLS_SCHEMES
                and not args.get("tls-sni-override")
                and not args.get("tls-sni-disable")
            ):
                args["tls-sni-override"] = host

            if not args.get("http-headers-file") and not _has_host_header(args):
                default_port = (
                    DEFAULT_HTTPS_PORT
                    if parts.scheme in TLS_SCHEMES
                    else DEFAULT_HTTP_PORT
                )
                host_value = (
                    f"{host}:{parts.port}"
                    if parts.port and parts.port != default_port
                    else host
                )
                _append_http_header(args, f"Host: {host_value}")

        wst_args = [exec_path, "client"]

        for arg_name, arg_data in args.items():
            flag = "-" if len(arg_name) == 1 else "--"

            if arg_data is None or arg_data is False:
                continue

            if arg_data is True:
                wst_args.append(f"{flag}{arg_name}")
            elif isinstance(arg_data, list | tuple):
                for value in arg_data:
                    wst_args.append(f"{flag}{arg_name}={value}")
            else:
                wst_args.append(f"{flag}{arg_name}={arg_data}")

        wst_args.append(server_str)

        return wst_args

    @staticmethod
    def parse_server_settings(config: dict):
        args = config.get("args")
        if not isinstance(args, dict):
            raise WstunnelConfigError("Config key 'args' is not set")

        server = args.get("server")
        if not isinstance(server, str) or not server.strip():
            raise WstunnelConfigError("Config key 'server' is not set")

        if "www.example.com" in server:
            raise WstunnelConfigError("Please set the server in the config")

        parts = urlsplit(server)
        if parts.scheme not in WSS_SCHEMES or not parts.hostname:
            raise WstunnelConfigError(f"Invalid server format: '{server}'")

        try:
            port = parts.port
        except ValueError as e:
            raise WstunnelConfigError(f"Invalid port in server '{server}'") from e

        endpoint_port = port or (
            DEFAULT_HTTPS_PORT
            if parts.scheme in ("wss", "https")
            else DEFAULT_HTTP_PORT
        )
        host = parts.hostname
        endpoint_ip = WstunnelConfig.resolve_dns(host)

        return server, host, endpoint_port, endpoint_ip

    @staticmethod
    def _load_dns_cache(cache_file: str) -> dict[str, str]:
        try:
            with open(cache_file, encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, ValueError):
            return {}

        if not isinstance(data, dict):
            return {}

        return {key: value for key, value in data.items() if isinstance(value, str)}

    @staticmethod
    def _save_dns_cache(cache_file: str, cache: dict[str, str]) -> None:
        try:
            directory = os.path.dirname(cache_file)
            if directory:
                os.makedirs(directory, exist_ok=True)

            tmp_file = f"{cache_file}.tmp"
            with open(tmp_file, "w", encoding="utf-8") as file:
                json.dump(cache, file)
            os.replace(tmp_file, cache_file)
        except OSError:
            # The cache is a best-effort fallback when DNS is unavailable.
            logger.warning("Unable to write DNS cache to %s", cache_file, exc_info=True)

    @staticmethod
    def _resolve_host(host: str) -> str | None:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            pass

        # Fall back to IPv6 (or any address family) for IPv6-only hosts.
        try:
            addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return None

        return addresses[0][4][0] if addresses else None

    @staticmethod
    def resolve_dns(host: str, cache_file: str = DNS_CACHE_FILE) -> str:
        if not host:
            raise WstunnelConfigError("Unable to resolve an empty hostname")

        ip = WstunnelConfig._resolve_host(host)

        if ip is None:
            cached = WstunnelConfig._load_dns_cache(cache_file).get(host)
            if cached:
                logger.warning(
                    "DNS resolution failed for %s, using cached IP %s", host, cached
                )
                return cached
            raise WstunnelConfigError(f"Unable to resolve DNS for '{host}'")

        cache = WstunnelConfig._load_dns_cache(cache_file)
        cache[host] = ip
        WstunnelConfig._save_dns_cache(cache_file, cache)

        return ip

    @staticmethod
    def parse_tunnel_settings(config: dict):
        args = config.get("args")
        if not isinstance(args, dict):
            raise WstunnelConfigError("Config key 'args' is not set")

        local_to_remote = args.get("local-to-remote")
        if not isinstance(local_to_remote, str) or not local_to_remote:
            raise WstunnelConfigError("Config key 'local-to-remote' is not set")

        match = re.fullmatch(
            r"(?P<proto>udp|tcp)://"
            r"(?P<listen_ip>\[[^\]]+\]|[^:/]+):(?P<listen_port>\d+):"
            r"(?P<remote_ip>\[[^\]]+\]|[^:/]+):(?P<remote_port>\d+)"
            r"(?:\?(?P<args>.*))?",
            local_to_remote,
        )

        if not match:
            raise WstunnelConfigError(
                f"Invalid local-to-remote format: '{local_to_remote}'"
            )

        def unbracket(value: str) -> str:
            if value.startswith("[") and value.endswith("]"):
                return value[1:-1]
            return value

        return (
            match.group("proto"),
            unbracket(match.group("listen_ip")),
            int(match.group("listen_port")),
            unbracket(match.group("remote_ip")),
            int(match.group("remote_port")),
            match.group("args") or "",
        )
