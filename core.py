from concurrent.futures import process
import copy
import hashlib
import ipaddress
import json
import logging
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import threading


import psutil
import wgconfig


class WStunnel:

    def __init__(self, config) -> None:
        self.args = copy.copy(config["wstunnel"])
        self.process: None | subprocess.Popen = None
        self.process_logger: None | threading.Thread = None

        self.log = logging.getLogger("wstunnel")
        self.log.info("Parsing config...")

        # Parse and validate executable path
        self.exec_path = self._init_path(config)
        self.log.info("Setting 'wstunnel_path' to '%s'", self.exec_path)

        # Parse and validate endpoint server
        self.server, self.host, self.endpoint_port, self.endpoint_ip = (
            self._init_server()
        )
        self.log.info("Using endpoint server at: %s", self.server)

        self.listen_ip, self.listen_port = self._init_local()
        self.log.info("Listening on: %s:%s", self.listen_ip, self.listen_port)

    def _init_path(self, config):
        path = config["app"].get("wstunnel_path")
        if path is None:
            self.log.warning("'wstunnel_path' key is not set, using default")

            path = r".\wstunnel.exe" if platform.system().lower() == "windows" else path
            path = "./wstunnel" if platform.system().lower() == "linux" else path

        if path is None or not os.path.exists(path):
            self.log.critical("Executable at '%s' does not exist", path)
            sys.exit(1)

        return path

    def _init_server(self):
        server = None

        for i, a in enumerate(self.args):
            if list(a.keys())[0] == "server":
                server = self.args.pop(i)["server"]

        if server is None or "www.example.com" in server:
            self.log.critical("Please configure the 'server' key wstunnel config")
            sys.exit(1)

        endpoint_proto, host = server.split("://")

        if len(host.split(":")) == 2:
            host, endpoint_port = host.split(":")
        else:
            endpoint_port = (
                443 if endpoint_proto == "wss" or endpoint_proto == "https" else 80
            )

        endpoint_ip = self._lookup_host(host)

        return server, host, endpoint_port, endpoint_ip

    def _init_local(self):
        # Parse local listening ip/port
        local_to_remote = None
        for a in self.args:
            if list(a.keys())[0] in ["local-to-remote", "L"]:
                local_to_remote = a.get("local-to-remote", a.get("L"))
                break

        if local_to_remote is None:
            self.log.critical(
                "Local listening server is not set, expected either ('local-to-remote', 'L')"
            )
            sys.exit(1)

        # TODO: add proper parsing (use regex)
        # udp://0.0.0.0:51820:127.0.0.1:51820?timeout_sec=0
        local_proto, local_to_remote = local_to_remote.split("://", 1)
        local_to_remote, _ = local_to_remote.split("?", 1)
        local_to_remote = local_to_remote.split(":")

        if len(local_to_remote) == 3:
            return "0.0.0.0", local_to_remote[0]
        else:
            return local_to_remote[0], local_to_remote[1]

    def _lookup_host(self, host: str):
        self.log.info("Looking up DNS / Validating IP for: '%s'", host)

        if not os.path.exists("dns.json"):
            with open("dns.json", "w", encoding="utf-8") as f:
                f.write(r"{}")

        with open("dns.json", "r", encoding="utf-8") as f:
            txt = f.read()

        if txt == "":
            dns_json = {}
        else:
            dns_json = json.loads(txt)

        try:
            ip = socket.gethostbyname(host)
            dns_json.update({host: ip})

        except socket.gaierror:
            self.log.warning(
                "DNS Lookup: Failed! Looking up cached entries for '%s' in dns.json",
                host,
            )
            ip = dns_json.get(host)

            if ip is None:
                self.log.critical(
                    "DNS Lookup: Unable to automatically determine ip for '%s'", host
                )
                sys.exit(1)

        with open("dns.json", "w", encoding="utf-8") as f:
            json.dump(dns_json, f)
        return ip

    def _pipe_to_logging(self):

        while self.is_running:
            output_std = self.process.stdout.readline()  # type: ignore
            if output_std != "":
                self.log.info(output_std.decode())
            time.sleep(0.1)
            # # if output_err != "":
            # #     self.log.error(output_err.decode())
            # print(self.process.poll())

    @property
    def is_running(self):
        return (
            isinstance(self.process, subprocess.Popen) and self.process.poll() is None
        )

    def start(self):
        self.log.info("Starting wstunnel...")

        if self.is_running:
            self.log.critical("Failed to start wstunnel. It is already running...")
            return False

        wst_args = [self.exec_path, "client"]
        wst_host = self.server

        for a in self.args:
            arg_name = list(a.keys())[0]
            arg_data = a[arg_name]

            flag = "-" if len(arg_name) == 1 else "--"

            if isinstance(arg_data, bool):
                if arg_data is True:
                    wst_args.append(f"{flag}{arg_data}")
            else:
                flag = "-" if len(arg_name) == 1 else "--"
                wst_args.append(f"{flag}{arg_name}={arg_data}")

        wst_args.append(wst_host)
        self.log.debug(wst_args)

        self.process = subprocess.Popen(
            wst_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            preexec_fn=os.setsid,
        )

        time.sleep(1)

        if self.is_running:
            self.process_logger = threading.Thread(target=self._pipe_to_logging)
            self.process_logger.start()

            self.log.info("Started wstunnel!")
            return True
        else:
            self.log.critical("Unable to start wstunnel.")
            return False

    def stop(self):
        if self.is_running:
            self.log.info("Stopping...")
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)

            time.sleep(1)
            if self.is_running:
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)  # type: ignore

            self.log.info("Stopped!")

        else:
            self.log.info("Process is already stopped")

        return True

    def restart(self):
        self.log.info("Restarting...")
        self.stop()
        self.start()

    def cleanup(self):
        self.stop()


class Wireguard:

    def __init__(self, config, wst: WStunnel) -> None:
        self.log = logging.getLogger("wireguard")
        self.tmp_dir = tempfile.mkdtemp()

        self.wst = wst
        # Parse and validate executable path
        self.exec_path = self._init_path(config)
        self.log.info("Setting 'wireguard_path' to '%s'", self.exec_path)

        # load config
        self.log.info("Parsing config...")
        self.tmp_conf, self.iface_name = self._init_tmp_config(config)

        # Replace endpoint ip
        self.log.info("Modifying wireguard config file...")
        self.wg_config = self._init_wg_config(self.tmp_conf, self.wst)

    def _init_path(self, config):
        self.log.debug("Getting Wireguard Path...")

        path = config["app"].get("wireguard_path")
        if path is None:
            self.log.warning("'wireguard_path' key is not set, using default")
            path = (
                r"C:\Program Files\WireGuard\wireguard.exe"
                if platform.system().lower() == "windows"
                else path
            )
            path = "/usr/bin/wg-quick" if platform.system().lower() == "linux" else path

        if path is None or not os.path.exists(path):
            self.log.fatal(f"Executable at '{path}' does not exist")
            sys.exit(1)

        return path

    def _init_tmp_config(self, config):
        if config["wireguard"].get("path") is not None:

            if config["wireguard"].get("str") is not None:
                self.log.warning("'path' key is set. The 'str' key is ignored")

            with open(config["wireguard"]["path"], encoding="utf-8") as f:
                self.log.info("Using conf file at: %s", config["wireguard"]["path"])
                wg_str = f.read()

        else:
            self.log.info("Using conf str")
            wg_str = config["wireguard"]["str"]

        str_hash = hashlib.md5(wg_str.encode()).hexdigest()

        # Create tmp file
        tmp_conf_path = os.path.join(self.tmp_dir, f"wg-wst-{str_hash[0:8]}.conf")
        iface_name = f"wg-wst-{str_hash[0:8]}"

        self.log.debug(f"Creating temporary conf at {tmp_conf_path}")
        with open(tmp_conf_path, "w", encoding="utf-8") as f:
            f.write(wg_str)

        return tmp_conf_path, iface_name

    def _init_wg_config(self, tmp_conf: str, wst: WStunnel):
        wg_config = wgconfig.WGConfig(tmp_conf)
        wg_config.read_file()

        allowed_ips = []
        peer_id = list(wg_config.peers.keys())[0]  # type: ignore

        self.log.debug(f"Allowing outgoing connection to {wst.endpoint_ip}")

        for ips in wg_config.peers[peer_id]["AllowedIPs"]:  # type: ignore

            if ips == "::/0" and platform.system().lower() == "windows":
                self.log.info("OS == windows, skipping AllowedIPs '::/0'")
                continue

            try:
                net1 = ipaddress.ip_network(ips)
                net2 = ipaddress.ip_network(wst.endpoint_ip + "/32")
                allowed_ips.extend(map(str, net1.address_exclude(net2)))  # type: ignore
            except (TypeError, ValueError) as e:
                self.log.warning(f"{e} - Appending {net1} to AllowedIPs anyways")
                allowed_ips.append(ips)

        if platform.system().lower() == "windows":
            self.log.debug("OS == windows, adding ['::/1','8000::/1'] to AllowedIPs")
            allowed_ips.extend(["::/1", "8000::/1"])

        self.log.debug(allowed_ips)

        allowed_ips = ", ".join(set(allowed_ips))
        wg_config.del_attr(peer_id, "AllowedIPs")
        wg_config.add_attr(peer_id, "AllowedIPs", allowed_ips)

        listen_ip = "127.0.0.1" if wst.listen_ip == "0.0.0.0" else wst.listen_ip

        self.log.debug(f"Changing endpoint to {listen_ip}:{wst.listen_port}")
        wg_config.del_attr(peer_id, "Endpoint")
        wg_config.add_attr(peer_id, "Endpoint", f"{listen_ip}:{wst.listen_port}")
        wg_config.write_file(tmp_conf)

        return wg_config

    @property
    def is_running(self):
        return self.iface_name in psutil.net_if_addrs()

    def remove_orphan_iface(self):
        for i in psutil.net_if_addrs().keys():

            if i == self.iface_name:
                self.log.warning(
                    f"The interface '{i}' exist this may be due to improperly stopped program"
                    + "or another instance is running. Attempting automatic removal"  # noqa
                )
                self.stop()

            elif i.startswith("wg-wst"):

                self.log.warning(
                    f"Found orphan '{i}' interface attempting automatic removal..."
                )

                if platform.system().lower() == "windows":
                    psc = subprocess.run(
                        [self.exec_path, "/uninstalltunnelservice", i], check=False
                    )

                    if psc.returncode == 0:
                        self.log.info(f"Successfully stopped '{i}'")
                    else:
                        self.log.critical(
                            f"Unable to remove wireguard interface: '{i}', \
                            please manually stop it before starting the program"
                        )
                        sys.exit(psc.returncode)

                else:
                    self.log.warning(
                        f"Unable to automatically remove wireguard interface: {i}, \
                        please manually stop it before starting the program"
                    )
                    sys.exit(1)

        time.sleep(1)

    def start(self):
        self.log.info(f"Starting {self.iface_name}...")

        self.remove_orphan_iface()

        if platform.system().lower() == "windows":
            action = "/installtunnelservice"
        else:
            action = "up"

        status = subprocess.run([self.exec_path, action, self.tmp_conf], check=False)

        if status.returncode == 0:
            self.log.info("Started wireguard!")
            return True
        else:
            self.log.critical(
                f"Unable to start wireguard. Program return status code of: {status.returncode}"
            )
            return False

    def stop(self):

        if self.is_running:
            self.log.info(f"Stopping {self.iface_name}...")

            if platform.system().lower() == "windows":
                action = "/uninstalltunnelservice"
                path = self.iface_name
            else:
                action = "down"
                path = self.tmp_conf

            status = subprocess.run([self.exec_path, action, path], check=False)

            if status.returncode == 0:
                self.log.info("Stopped!")
                return True
            else:
                self.log.critical(
                    f"Unable to stop. Program return status code of: {status.returncode}"
                )
                return False
        else:
            self.log.info("Tunnel cannot be found / is already stopped")
            return True

    def restart(self):
        self.stop()
        self.start()

    def cleanup(self):
        self.stop()

        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)

    def save(self):
        shutil.copyfile(self.tmp_conf, self.iface_name + ".conf")

    def __del__(self):
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)
