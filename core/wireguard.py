import hashlib
import ipaddress
import logging
import os
import platform
import subprocess
import time
from dataclasses import dataclass

import psutil
from wgconfig import WGConfig

from .process import Process
from .wstunnel import WstunnelConfig

CONFIG_FOLDER = "./conf/"


class WireguardError(Exception):
    pass


class WireguardConfigError(WireguardError):
    pass


class WireguardRuntimeError(WireguardError):
    pass


@dataclass
class WireguardConfig:
    exec_path: str
    exec_up_args: list[str]
    exec_down_args: list[str]
    iface_name: str
    conf_path: str
    conf: WGConfig

    @staticmethod
    def init(config: dict, wst_config: WstunnelConfig) -> "WireguardConfig":

        exec_path = WireguardConfig.parse_exec_path(config)
        conf_path, iface_name, wg_config = WireguardConfig.create_config_file(
            config, wst_config
        )
        start, stop = WireguardConfig.generate_exec_args(
            exec_path, iface_name, conf_path
        )

        return WireguardConfig(
            exec_path=exec_path,
            exec_up_args=start,
            exec_down_args=stop,
            iface_name=iface_name,
            conf_path=conf_path,
            conf=wg_config,
        )

    @staticmethod
    def parse_exec_path(config):
        try:
            plat = platform.system().lower()
            path = config["path"].get(plat)

        except KeyError as e:
            raise WireguardConfigError(f"Config key 'path' for {plat} is not set {e}")

        return path

    @staticmethod
    def generate_exec_args(exec_path: str, iface_name: str, wg_path: str):

        up = "/installtunnelservice" if platform.system() == "Windows" else "up"
        down = "/uninstalltunnelservice" if platform.system() == "Windows" else "down"
        path = iface_name if platform.system() == "Windows" else wg_path

        return [exec_path, up, wg_path], [exec_path, down, path]

    @staticmethod
    def create_config_file(config, wst: WstunnelConfig):

        try:
            wg_path = config["config"].get("path")

            if wg_path is not None:
                with open(wg_path, encoding="utf-8") as f:
                    wg_str = f.read()
            else:
                wg_str = config["config"]["str"]

            str_hash = hashlib.md5(wg_str.encode()).hexdigest()
            iface_name = f"wg-wst-{str_hash[0:8]}"
            conf_path = os.path.join(CONFIG_FOLDER, f"{iface_name}.conf")
            conf_path = os.path.abspath(conf_path)

            os.makedirs(os.path.dirname(conf_path), exist_ok=True)

            with open(conf_path, "w", encoding="utf-8") as f:
                f.write(wg_str)

            wg_config = WGConfig(conf_path)
            wg_config.read_file()

            allowed_ips = []
            peer_id = list(wg_config.peers.keys())[0]  # type: ignore

            for ips in wg_config.peers[peer_id]["AllowedIPs"]:  # type: ignore

                if ips == "::/0" and platform.system().lower() == "windows":
                    continue

                try:
                    net1 = ipaddress.ip_network(ips)
                    net2 = ipaddress.ip_network(wst.endpoint_ip + "/32")
                    allowed_ips.extend(map(str, net1.address_exclude(net2)))  # type: ignore

                except (TypeError, ValueError) as e:
                    allowed_ips.append(ips)

            if platform.system().lower() == "windows":
                allowed_ips.extend(["::/1", "8000::/1"])

            allowed_ips = ", ".join(set(allowed_ips))
            wg_config.del_attr(peer_id, "AllowedIPs")
            wg_config.add_attr(peer_id, "AllowedIPs", allowed_ips)

            listen_ip = "127.0.0.1" if wst.listen_ip == "0.0.0.0" else wst.listen_ip

            wg_config.del_attr(peer_id, "Endpoint")
            wg_config.add_attr(peer_id, "Endpoint", f"{listen_ip}:{wst.listen_port}")

            wg_config.write_file(conf_path)

            return conf_path, iface_name, wg_config

        except Exception as e:
            raise WireguardConfigError(
                f"An error occurred processing wireguard file: {e}"
            )


class WireguardProcess(Process):
    def __init__(self, config: WireguardConfig) -> None:
        self.log = logging.getLogger("WireguardProcess")
        self.config = config

    def get_status(self):
        return "running" if self.is_running else "stopped"

    @property
    def is_running(self):
        return self.config.iface_name in psutil.net_if_addrs()

    def reset(self):
        if self.is_running:
            self.log.warning("Found unstopped wireguard interface, removing...")
            self.stop()

    def start(self):
        self.reset()
        self.log.info("Starting wireguard...")

        try:
            subprocess.run(self.config.exec_up_args, check=True)
            self.log.info("Started wireguard!")

        except subprocess.CalledProcessError as e:
            raise WireguardRuntimeError(f"Unable to start wireguard {e}")

    def stop(self):
        if self.is_running:
            try:
                self.log.info("Stopping wireguard...")
                subprocess.run(self.config.exec_down_args, check=True)

                while self.is_running:
                    time.sleep(0.1)

                self.log.info("Stopped wireguard!")
                time.sleep(3)  # wait some time for wireguard cli to work

            except subprocess.CalledProcessError as e:
                raise WireguardRuntimeError(f"Unable to stop wireguard. {e}")

    def restart(self):
        self.log.info("Restarting...")
        self.stop()

        while self.is_running:
            time.sleep(0.1)

        self.start()
