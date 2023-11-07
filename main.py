#!/usr/bin/env python3

import argparse
import atexit
import ctypes
import hashlib
import ipaddress
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import json

import platform
import psutil
import requests
import wgconfig
import yaml

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(name)s - %(message)s'
)

# global variables

SYSTEM_OS = platform.system().lower()
EXIT_TIMER = 5
active_processes = []
logger = logging.getLogger("app")


class WStunnel:

    def __init__(self, path, wst_config) -> None:
        self.args = wst_config
        self.process = None

        self.log = logging.getLogger("wstunnel")
        self.log.info("Parsing config...")

        # Parse and validate executable path
        if path == None:
            self.log.warning(
                "'wstunnel_path' key is not set, using default path")

            path = r".\wstunnel.exe" if SYSTEM_OS == 'windows' else path
            path = "./wstunnel" if SYSTEM_OS == 'linux' else path

        self.log.info(f"Setting 'wstunnel_path' to '{path}'")

        if path == None or not os.path.exists(path):
            self.log.fatal(f"Executable at '{path}' does not exist")
            sys.exit(1)

        self.exec_path = path

        # Parse and validate endpoint server
        self.server = None
        for i, a in enumerate(self.args):
            if list(a.keys())[0] == 'server':
                self.server = self.args.pop(i)["server"]

        if self.server == None or "www.example.com" in self.server:
            self.log.fatal(
                f"Please configure the 'server' key wstunnel config")
            sys.exit(1)

        if "wss://" not in self.server and "ws://" not in self.server:
            self.log.fatal(f"Expected either 'wss: //' or 'ws: //' protocol")
            sys.exit(1)

        endpoint_proto, host = self.server.split("://")

        if len(host.split(':')) == 2:
            host, endpoint_port = host.split(':')
        else:
            endpoint_port = 443 if endpoint_proto == 'wss' else 80

        self.log.info(f"Using endpoint server at: {self.server}")

        self.host = host
        self.endpoint_proto = endpoint_proto
        self.endpoint_port = endpoint_port
        self.endpoint_ip = self._lookup_host(self.host)

        # Parse local listening ip/port
        local_server = None
        for i, a in enumerate(self.args):
            if list(a.keys())[0] in ['local-to-remote', 'L']:
                local_server = a.get('local-to-remote', a.get('L'))
                break

        if local_server == None:
            self.log.fatal(
                f"Local listening server is not set, expected either ('local-to-remote', 'L')")
            sys.exit(1)

        # TODO: add proper parsing (use regex)
        local_server, _ = local_server.split("?", 1)
        local_proto, local_server = local_server.split("://")
        local_server = local_server.split(":")

        if len(local_server) == 1 or len(local_server) == 3:
            self.listen_port = local_server[0]
            self.listen_ip = '0.0.0.0'
        else:
            self.listen_port = local_server[1]
            self.listen_ip = local_server[0]

        self.log.info(f"listening on: {self.listen_ip}: {self.listen_port}")

    def _lookup_host(self, host: str):
        self.log.info(f"Looking up DNS / Validating IP for: '{host}'")

        if not os.path.exists("dns.json"):
            with open('dns.json', 'w') as f:
                f.write(r"{}")

        with open("dns.json", 'r+') as f:
            txt = f.read()

            if txt == '':
                dns_json = {}
            else:
                dns_json = json.loads(txt)

            try:
                ip = socket.gethostbyname(host)
                dns_json.update({host: ip})

            except:
                self.log.warning(f"DNS Lookup: Failed! Looking up cached entries for '{host}' in dns.json")
                ip = dns_json.get(host)

                if ip == None:
                    self.log.critical(
                        f"DNS Lookup: Unable to automatically determine ip for '{host}'")
                    sys.exit(1)

            f.seek(0)
            json.dump(dns_json, f)
            return ip

    def start(self):
        self.log.info("Starting wstunnel...")

        wst_args = [self.exec_path, 'client']
        wst_host = self.server

        for a in self.args:
            arg_name = list(a.keys())[0]
            arg_data = a[arg_name]

            flag = '-' if len(arg_name) == 1 else '--'

            if isinstance(arg_data, bool):
                if arg_data == True:
                    wst_args.append(f"{flag}{arg_data}")
            else:
                flag = '-' if len(arg_name) == 1 else '--'
                wst_args.append(f"{flag}{arg_name}={arg_data}")

        wst_args.append(wst_host)
        self.log.debug(wst_args)

        self.process = subprocess.Popen(wst_args)

        time.sleep(0.5)
        if self.process.poll() == None:
            self.log.info("Started wstunnel!")
            return True
        else:
            self.log.critical("Unable to start wstunnel.")
            return False

    def stop(self):
        if self.process != None:
            self.log.info("Stopping...")
            self.process.terminate()

            while self.process.poll() == None:
                time.sleep(0.1)

            self.log.info("Stopped!")

    def restart(self):
        self.log.info("Restarting...")
        self.stop()
        self.start()

    def cleanup(self):
        self.stop()


class Wireguard:

    def __init__(self, path, config, wst: WStunnel) -> None:
        self.log = logging.getLogger("wireguard")
        self.wst = wst
        self.started = False

        # Parse and validate executable path
        if path == None:
            self.log.warning(
                "'wireguard_path' key is not set, using default paths")
            path = r"C:\Program Files\WireGuard\wireguard.exe" if SYSTEM_OS == 'windows' else path
            path = "/usr/bin/wg-quick" if SYSTEM_OS == 'linux' else path

        self.log.info(f"Setting 'wireguard_path' to '{path}'")

        if path == None or not os.path.exists(path):
            self.log.fatal(f"Executable at '{path}' does not exist")
            sys.exit(1)

        self.exec_path = path

        # load config
        self.log.info("Parsing config...")

        if config.get('path'):

            if config.get('str') != None:
                self.log.warning("'path' key is set. The 'str' key is ignored")

            with open(config['path']) as f:
                self.log.info(f"Using conf file at: {config['path']}")
                wg_str = f.read()

        else:
            self.log.info(f"Using conf str")
            wg_str = config['str']

        str_hash = hashlib.md5(wg_str.encode()).hexdigest()

        # Create tmp file
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_conf = os.path.join(
            self.tmp_dir,
            f'wg-wst-{str_hash[0:8]}.conf'
        )
        self.iface_name = os.path.basename(self.tmp_conf).replace('.conf', '')
        self.log.debug(f"Creating temporary conf at {self.tmp_conf}")

        with open(self.tmp_conf, 'w') as f:
            f.write(wg_str)

        # Replace endpoint ip with wg_config
        wg_config = wgconfig.WGConfig(self.tmp_conf)
        wg_config.read_file()

        allowed_ips = []
        peer_id = list(wg_config.peers.keys())[0]

        self.log.info(f"Allowing outgoing connection to {wst.endpoint_ip}")

        for ips in wg_config.peers[peer_id]["AllowedIPs"]:

            if ips == "::/0" and SYSTEM_OS == 'windows':
                self.log.info("OS == windows, skipping AllowedIPs '::/0'")
                continue

            try:
                net1 = ipaddress.ip_network(ips)
                net2 = ipaddress.ip_network(wst.endpoint_ip + "/32")
                allowed_ips.extend(
                    map(str, net1.address_exclude(net2))
                )
            except (TypeError, ValueError) as e:
                self.log.warning(
                    f"{e} - Appending {net1} to AllowedIPs anyways")
                allowed_ips.append(ips)

        if SYSTEM_OS == 'windows':
            self.log.info("OS == windows, adding ['::/1','8000::/1'] to AllowedIPs")
            allowed_ips.extend(["::/1", "8000::/1"])

        self.log.debug(allowed_ips)

        allowed_ips = ", ".join(set(allowed_ips))
        wg_config.del_attr(peer_id, "AllowedIPs")
        wg_config.add_attr(peer_id, "AllowedIPs", allowed_ips)

        listen_ip = '127.0.0.1' if wst.listen_ip == '0.0.0.0' else wst.listen_ip

        self.log.info(f"Changing endpoint to {listen_ip}:{wst.listen_port}")
        wg_config.del_attr(peer_id, "Endpoint")
        wg_config.add_attr(peer_id, "Endpoint", f"{listen_ip}:{wst.listen_port}")
        wg_config.write_file(self.tmp_conf)

        self.wg_config = wg_config

    def remove_orphan_iface(self):
        for i in psutil.net_if_addrs().keys():
            self.log.debug(f"{i} == {self.iface_name}: {i == self.iface_name}")

            if i == self.iface_name:
                self.log.warning(
                    f"The interface '{self.iface_name}' exist this may be due to improperly stopped program or another instance is running. Attempting automatic removal")
                self.stop()

            elif i.startswith('wg-wst'):
                if SYSTEM_OS == 'windows':
                    self.log.warning(
                        f"Found orphan '{self.iface_name}' interface attempting automatic removal...")
                    subprocess.run([
                        self.exec_path, '/uninstalltunnelservice', i])
                else:
                    self.log.warning(
                        f"Unable to automatically remove wireguard interface: {i}")

        time.sleep(1)

    def start(self):
        self.log.info(f"Starting {self.iface_name}...")

        self.remove_orphan_iface()

        if SYSTEM_OS == 'windows':
            action = "/installtunnelservice"
        else:
            action = 'up'

        status = subprocess.run([
            self.exec_path,
            action,
            self.tmp_conf
        ])

        if status.returncode == 0:
            self.log.info("Started wireguard!")
        else:
            self.log.critical(
                f"Unable to start. Program return status code of: {status.returncode}")
            sys.exit(status.returncode)

        self.started = True if status.returncode == 0 else False
        return self.started

    def stop(self):
        self.log.info(f"Stopping {self.iface_name}...")

        if SYSTEM_OS == 'windows':
            action = "/uninstalltunnelservice"
            path = self.iface_name
        else:
            action = 'down'
            path = self.tmp_conf

        status = subprocess.run([
            self.exec_path,
            action,
            path
        ])

        if status.returncode == 0:
            self.log.info("Stopped!")
            self.started = False
        else:
            self.log.critical(
                f"Unable to stop. Program return status code of: {status.returncode}")
        
        return not self.started

    def cleanup(self):
        if self.started:
            self.stop()

        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)

    def save(self):
        shutil.copyfile(self.tmp_conf, self.iface_name + ".conf")

    def __del__(self):
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)


def elevate_user():
    logger.info("Elevating to superuser / admin")

    if SYSTEM_OS == 'windows':
        if not ctypes.windll.shell32.IsUserAnAdmin():
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)

    elif SYSTEM_OS == 'linux':
        if os.geteuid() != 0:
            os.system("sudo echo")

    else:
        if os.geteuid() != 0:
            logger.fatal(
                "Unknown/Unsupported OS. Please program run as superuser")
            sys.exit(1)


def get_public_ip(timeout=5):
    try:
        res = requests.get("https://api.ipify.org", timeout=timeout)
        res.raise_for_status()

        return res.text

    except Exception as e:
        logger.debug(f"Unable to fetch Public IP")
        logger.debug(e)
        return None


def healthcheck_ip(old_ip, sleep=5, max_it=5):

    for _ in range(max_it):
        time.sleep(sleep)
        new_ip = get_public_ip(1)

        if new_ip == None:
            logger.warning(
                f"Health Check IP: Failed! Unable to fetch Public IP. Your traffic may not be tunneled!")

            continue

        elif old_ip == None and new_ip != None:
            logger.warning(
                f"Health Check IP: Unknown Status! Unable to compare old_ip: {old_ip} with new_ip: {new_ip}. Your traffic may not be tunneled!")

            return True

        elif old_ip == new_ip:
            logger.warning(
                f"Health Check IP: Failed! Your new_ip: {new_ip} = old_ip: {old_ip}. Your traffic may not be tunneled!")

            continue

        else:
            logger.info(
                f"Health Check IP: Success! Your new Public IP is: {new_ip}")

            return True

    logger.warning(
        f"Health Check IP: Max iteration reached! Discontinuing IP health check.")

    return False


def healthcheck_ping(wstunnel: WStunnel, restart_wstunnel=True):
    servers = [wstunnel.endpoint_ip, '1.1.1.1', '8.8.8.8']
    flag = '-n' if SYSTEM_OS == 'windows' else '-c'

    for s in servers:
        res = subprocess.call(
            ["ping", flag, '1', s], stdout=subprocess.PIPE)

        if res == 0:
            logger.debug(
                f"Health Check Ping: Success! Server: {s}")
            break

    if res != 0:
        logger.warning(
            f"Health Check Ping: Failed! Unable to ping {servers}")

        if restart_wstunnel:
            logger.warning(
                f"Health Check Ping: Restarting wstunnel...")

            wstunnel.restart()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Wireguard over wstunnel")
    parser.add_argument(
        '--config', '-c', help="Path to program config", default='./config.yml')
    parser.add_argument(
        '--clean', help="Clean wireguard tunnel that are not properly stopped", action='store_true')
    parser.add_argument(
        '--log_level', help="Set logging level", default='INFO')

    args = parser.parse_args()

    logger.setLevel(args.log_level)

    with open(args.config) as f:
        logger.info("Loading app config...")
        config = yaml.full_load(f)

    logger.info(f"Detected OS: {SYSTEM_OS}")

    elevate_user()

    try:
        wstunnel = WStunnel(config["app"].get(
            "wstunnel_path"), config["wstunnel"])
        wireguard = Wireguard(config["app"].get(
            "wireguard_path"), config['wireguard'], wstunnel)

        if args.clean == True:
            logger.info(
                "--clean is set, attempting removal of orphaned interface")
            wireguard.remove_orphan_iface()
            sys.exit(0)

        logger.info("Fetching current Public IP...")

        old_ip = get_public_ip(
            1) if config['app']['healthcheck_ip_tries'] != 0 else None

        if config['app']['start_wstunnel'] == True:

            if wstunnel.start() == True:
                active_processes.append(wstunnel)
                time.sleep(0.5)

        if config['app']['start_wireguard'] == True:

            if wireguard.start() == True:
                active_processes.append(wireguard)

        if config['app']['export_wireguard_conf'] == True:
            wireguard.save()

        logger.info(f"Press CTRL + C to exit")

        healthcheck_ip(old_ip, max_it=config['app']['healthcheck_ip_tries'])

        while True:
            if config['app']['healthcheck_ping_interval'] > 0:
                healthcheck_ping(wstunnel, restart_wstunnel=True)
                time.sleep(config['app']['healthcheck_ping_interval'])
            else:
                time.sleep(9999)
        

    except (KeyboardInterrupt, SystemExit):
        pass

    except:
        logger.critical("Caught an exception. exiting...", exc_info=True)


@atexit.register
def cleanup():
    s1 = signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    logger.info("Cleaning Up...")
    for p in active_processes:
        p.cleanup()

    logger.info("Cleanup Complete!")
    logger.info(
        f"Exiting in {EXIT_TIMER}s. Press CTRL + C to stop, spam it to exit now")

    try:
        signal.signal(signal.SIGINT, s1)
        time.sleep(EXIT_TIMER)
    except:
        try:
            input("***** Press Enter or CTRL + C to Exit *****")
        except:
            pass
