import json
import logging
import os
import platform
import re
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass

from .process import Process


class WstunnelError(Exception):
    pass


class WstunnelConfigError(WstunnelError):
    pass


class WstunnelRuntimeError(WstunnelError):
    pass


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

    @staticmethod
    def init(config: dict) -> "WstunnelConfig":

        path = WstunnelConfig.parse_exec_path(config)
        server, host, endpoint_port, endpoint_ip = WstunnelConfig.parse_server_settings(
            config
        )
        proto, listen_ip, listen_port, remote_ip, remote_port, connect_args = (
            WstunnelConfig.parse_tunnel_settings(config)
        )
        return WstunnelConfig(
            exec_path=path,
            exec_args=WstunnelConfig.generate_exec_args(config),
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
    def parse_exec_path(config):
        plat = platform.system().lower()
        try:
            path = config["path"][plat]
        except KeyError:
            raise WstunnelConfigError(f"Config key 'path' for {plat} is not set")
        return path

    @staticmethod
    def generate_exec_args(config):
        wst_args = [WstunnelConfig.parse_exec_path(config), "client"]

        args = config.get("args").copy()
        server = args.pop("server")

        for arg_name, arg_data in args.items():
            flag = "-" if len(arg_name) == 1 else "--"

            if isinstance(arg_data, bool) and arg_data is True:
                wst_args.append(f"{flag}{arg_data}")
            else:
                wst_args.append(f"{flag}{arg_name}={arg_data}")

        wst_args.append(server)

        return wst_args

    @staticmethod
    def parse_server_settings(config):
        try:
            server = config["args"]["server"]
        except KeyError:
            raise WstunnelConfigError("Config key 'server' is not set")

        if "www.example.com" in server:
            raise WstunnelConfigError("Please set the server in the config")

        match = re.match(
            r"^(?P<proto>wss|ws|https|http):\/\/(?P<host>[^:\/]+)(:(?P<port>\d+))?",
            server,
        )

        if not match:
            raise WstunnelConfigError("Invalid server format")

        endpoint_proto = match.group("proto")
        host = match.group("host")
        endpoint_port = int(
            match.group("port") or (443 if endpoint_proto in ["wss", "https"] else 80)
        )
        endpoint_ip = WstunnelConfig.resolve_dns(host)

        return server, host, endpoint_port, endpoint_ip

    @staticmethod
    def resolve_dns(host, cache_file="conf/dns.json"):
        cache = {}
        if os.path.exists(cache_file):
            with open(cache_file, "r") as file:
                cache = json.load(file)

        try:
            ip = socket.gethostbyname(host)
            cache[host] = ip
            with open(cache_file, "w") as file:
                json.dump(cache, file)
        except socket.gaierror:
            if host in cache:
                ip = cache[host]
            else:
                raise WstunnelConfigError("Unable to resolve DNS.")

        return ip

    @staticmethod
    def parse_tunnel_settings(config):
        try:
            local_to_remote = config["args"]["local-to-remote"]
        except KeyError:
            raise WstunnelConfigError("Config key 'local-to-remote' is not set")

        match = re.match(
            r"^(?P<proto>udp|tcp):\/\/(?P<listen_ip>[^:]+):(?P<listen_port>\d+):(?P<remote_ip>[^:]+):(?P<remote_port>\d+)\??(?P<args>.*)?",
            local_to_remote,
        )

        if not match:
            raise WstunnelConfigError("Invalid local_to_remote format")

        proto = match.group("proto")
        listen_ip = match.group("listen_ip")
        listen_port = int(match.group("listen_port"))
        remote_ip = match.group("remote_ip")
        remote_port = int(match.group("remote_port"))
        args = match.group("args")

        return proto, listen_ip, listen_port, remote_ip, remote_port, args


class WstunnelProcess(Process):
    def __init__(self, config: WstunnelConfig) -> None:
        self.log = logging.getLogger("WstunnelProcess")
        self.config = config

        self.process: subprocess.Popen = None  # type: ignore
        self.process_logger_thread = None  # type: ignore

    def _logger_process(self):
        while self.is_running:
            output_std = self.process.stdout.readline()  # type: ignore
            if output_std is not None:
                self.log.info(str(output_std.strip(), "utf-8"))
            time.sleep(0.01)

    def get_status(self):
        return "running" if self.is_running else "stopped"

    @property
    def is_running(self):
        return self.process and self.process.poll() is None

    def start(self):

        self.log.info("Starting...")

        kw = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            # "shell": True,
        }

        if platform.system() == "Windows":
            kw.setdefault("creationflags", subprocess.CREATE_NEW_PROCESS_GROUP)
        else:
            kw.setdefault("preexec_fn", os.setsid)  # type: ignore

        self.process = subprocess.Popen(self.config.exec_args, **kw)  # type: ignore

        start_time = time.time()
        timeout = 3  # seconds

        while time.time() - start_time < timeout:
            if self.is_running:
                self.process_logger_thread = threading.Thread(
                    target=self._logger_process, daemon=True
                )

                self.process_logger_thread.start()

                time.sleep(3)
                # begin dns resolution for wstunnel
                target_ip = (
                    "127.0.0.1"
                    if self.config.listen_ip == "0.0.0.0"
                    else self.config.listen_ip
                )
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(
                        "start".encode(),
                        (target_ip, self.config.listen_port),
                    )

                time.sleep(3)

                self.log.info("Started wstunnel!")

                return

            time.sleep(0.1)

        self.log.critical(
            "Unable to start wstunnel. Process returned a status code of: %s. %s",
            self.process.returncode,
            self.process.stderr.read().decode().strip(),  # type: ignore
        )

        raise WstunnelRuntimeError("Unable to start wstunnel")

    def stop(self):

        if self.is_running:
            self.log.info("Stopping...")

            if platform.system() == "Windows":
                self.log.debug("Stopping using CTRL_BREAK_EVENT")
                self.process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self.log.debug("Stopping using SIGTERM")
                self.process.terminate()

            # Wait for the process to terminate
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.log.warning(
                    "Process did not terminate within 10 seconds, killing it"
                )
                self.process.kill()
                self.process.wait()

            self.log.info("Stopped wstunnel")

    def restart(self):
        self.log.info("Restarting...")
        self.stop()
        time.sleep(1)
        self.start()

    def cleanup(self):
        self.stop()
