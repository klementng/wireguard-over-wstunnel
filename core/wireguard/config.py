import contextlib
import hashlib
import ipaddress
import os
import platform
from dataclasses import dataclass
from typing import TYPE_CHECKING

from wgconfig import WGConfig

from ..exception import ExecutableNotFoundError, WireguardConfigError
from ..logger import logger
from ..utils.system import require_executable

if TYPE_CHECKING:
    from ..wstunnel import WstunnelConfig

CONFIG_FOLDER = "./conf/"
WIREGUARD_RUN_DIR = "/var/run/wireguard"
IFACE_PREFIX = "wg-wst-"


@dataclass
class WireguardConfig:
    exec_path: str
    exec_up_args: list[str]
    exec_down_args: list[str]
    iface_name: str
    conf_path: str
    conf: "WGConfig | None"

    @classmethod
    def init(
        cls, config: dict, wst_config: "WstunnelConfig | None" = None
    ) -> "WireguardConfig":
        """Validate settings; omit the transport only when preparing cleanup."""
        if not isinstance(config, dict):
            raise WireguardConfigError("wireguard must be a mapping")

        paths = config.get("path")
        if not isinstance(paths, dict):
            raise WireguardConfigError("wireguard.path must be a mapping")

        wg_config = config.get("config")
        if not isinstance(wg_config, dict):
            raise WireguardConfigError("wireguard.config must be a mapping")
        if not wg_config.get("path") and not wg_config.get("str"):
            raise WireguardConfigError("wireguard.config must define 'path' or 'str'")

        plat = platform.system().lower()
        path = paths.get(plat)
        if not path:
            raise WireguardConfigError(f"Config key 'path.{plat}' is not set")
        try:
            exec_path = require_executable(str(path), f"wireguard.path.{plat}")
        except ExecutableNotFoundError as e:
            raise WireguardConfigError(str(e)) from e
        if wst_config is None:
            wg_str = cls._load_wg_string(config)
            iface_name = cls._interface_name(wg_str)
            conf_path = os.path.abspath(os.path.join(CONFIG_FOLDER, f"{iface_name}.conf"))
            return cls(
                exec_path=exec_path,
                exec_up_args=[],
                exec_down_args=[],
                iface_name=iface_name,
                conf_path=conf_path,
                conf=None,
            )

        conf_path, iface_name, wg_config = cls.create_config_file(config, wst_config)
        up = "/installtunnelservice" if plat == "windows" else "up"
        result = cls(
            exec_path=exec_path,
            exec_up_args=[exec_path, up, conf_path],
            exec_down_args=[],
            iface_name=iface_name,
            conf_path=conf_path,
            conf=wg_config,
        )
        result.exec_down_args = result.exec_down_args_for(iface_name)
        return result

    def exec_down_args_for(self, iface_name: str) -> list[str]:
        """Build the command needed to tear down an arbitrary wg-wst-* interface."""
        is_windows = platform.system() == "Windows"
        down = "/uninstalltunnelservice" if is_windows else "down"
        path = (
            iface_name
            if is_windows
            else os.path.abspath(os.path.join(CONFIG_FOLDER, f"{iface_name}.conf"))
        )
        return [self.exec_path, down, path]

    @staticmethod
    def _exclude_endpoint(allowed_ips: list[str], endpoint_ip: str) -> list[str]:
        try:
            endpoint = ipaddress.ip_address(endpoint_ip)
        except ValueError:
            logger.warning(
                "Unable to exclude endpoint '%s' from AllowedIPs", endpoint_ip
            )
            return list(allowed_ips)

        prefix = 32 if endpoint.version == 4 else 128
        endpoint_net = ipaddress.ip_network(f"{endpoint_ip}/{prefix}", strict=False)

        result: list[str] = []
        for entry in allowed_ips:
            try:
                network = ipaddress.ip_network(entry)
                if network.version != endpoint_net.version:
                    result.append(entry)
                elif endpoint_net.subnet_of(network):
                    result.extend(map(str, network.address_exclude(endpoint_net)))
                else:
                    result.append(entry)
            except ValueError:
                logger.warning(
                    "Ignoring invalid AllowedIPs entry: %s", entry
                )
                result.append(entry)

        return result

    @staticmethod
    def _load_wg_string(config: dict) -> str:
        wg_config_section = config.get("config")
        if not isinstance(wg_config_section, dict):
            raise WireguardConfigError("Config key 'config' is not set")

        wg_path = wg_config_section.get("path")
        if wg_path is not None:
            try:
                with open(wg_path, encoding="utf-8") as f:
                    return f.read()
            except OSError as e:
                raise WireguardConfigError(
                    f"Unable to read wireguard config '{wg_path}': {e}"
                ) from e

        wg_str = wg_config_section.get("str")
        if not isinstance(wg_str, str) or not wg_str.strip():
            raise WireguardConfigError(
                "wireguard config must define 'path' or a non-empty 'str'"
            )
        return wg_str

    @staticmethod
    def _interface_name(wg_str: str) -> str:
        str_hash = hashlib.sha256(wg_str.encode()).hexdigest()
        return f"{IFACE_PREFIX}{str_hash[0:8]}"

    @staticmethod
    def create_config_file(config: dict, wst: "WstunnelConfig"):
        try:
            wg_str = WireguardConfig._load_wg_string(config)
            iface_name = WireguardConfig._interface_name(wg_str)
            conf_path = os.path.abspath(
                os.path.join(CONFIG_FOLDER, f"{iface_name}.conf")
            )

            os.makedirs(os.path.dirname(conf_path), exist_ok=True)

            with open(conf_path, "w", encoding="utf-8") as f:
                f.write(wg_str)

            with contextlib.suppress(OSError):
                # The generated config contains the private key.
                os.chmod(conf_path, 0o600)

            wg_config = WGConfig(conf_path)
            wg_config.read_file()

            if not wg_config.interface.get("PrivateKey"):
                raise WireguardConfigError(
                    "wireguard [Interface] is missing 'PrivateKey'"
                )
            if not wg_config.interface.get("Address"):
                raise WireguardConfigError("wireguard [Interface] is missing 'Address'")

            if not wg_config.peers:
                raise WireguardConfigError("wireguard config has no [Peer] section")

            is_windows = platform.system().lower() == "windows"
            listen_ip = "127.0.0.1" if wst.listen_ip == "0.0.0.0" else wst.listen_ip

            for peer_id, peer in wg_config.peers.items():
                allowed_ips = list(peer.get("AllowedIPs", []))

                if is_windows:
                    # Windows does not accept a default IPv6 route; split it in two.
                    expanded: list[str] = []
                    for ip in allowed_ips:
                        if ip == "::/0":
                            expanded.extend(["::/1", "8000::/1"])
                        else:
                            expanded.append(ip)
                    allowed_ips = expanded

                allowed_ips = WireguardConfig._exclude_endpoint(
                    allowed_ips, wst.endpoint_ip
                )

                allowed_ips = ", ".join(dict.fromkeys(allowed_ips))

                if "AllowedIPs" in peer:
                    wg_config.del_attr(peer_id, "AllowedIPs")
                wg_config.add_attr(peer_id, "AllowedIPs", allowed_ips)

                if "Endpoint" in peer:
                    wg_config.del_attr(peer_id, "Endpoint")
                wg_config.add_attr(
                    peer_id, "Endpoint", f"{listen_ip}:{wst.listen_port}"
                )

            wg_config.write_file(conf_path)

            return conf_path, iface_name, wg_config

        except WireguardConfigError:
            raise
        except Exception as e:
            raise WireguardConfigError(
                f"An error occurred processing wireguard file: {e}"
            ) from e
