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
    level=logging.DEBUG,
    format='%(levelname)s - %(message)s'
)

# global variables

logger = logging.getLogger()


class WStunnel:

    def __init__(self, gconfig) -> None:
        logger.info("[wstunnel] Loading config...")

        self.os = platform.system().lower()

        try:
            self.exec_path = gconfig["app"]["wstunnel_path"]
        except KeyError:
            if self.os == 'windows':
                logger.info("[wstunnel] 'wstunnel_path' key is not set. Setting wstunnel_path to '.\wstunnel.exe'")
                self.exec_path = ".\wstunnel.exe"
            
            elif self.os == 'linux':
                logger.info("[wstunnel] 'wstunnel_path' key is not set. Setting wstunnel_path to './wstunnel-linux-x64'")
                self.exec_path = "./wstunnel-linux-x64"
            
            else:
                logger.critical(f"[wstunnel] Unknown/Unsupported OS: '{self.os}', please manually set 'wstunnel_path' key under 'app' section")
                sys.exit(1)
                
        self.args = gconfig['wstunnel']
        self.process = None

        # Parse Endpoint Server
        proto, host = self.args.pop('server').split("://")

        if len(host.split(':')) == 2:
            host, endpoint_port = host.split(':')
        else:
            endpoint_port = 443 if proto == 'wss://' else 80

        endpoint_ip = self._lookup_host(host)

        self.server = f"{proto}://{endpoint_ip}:{endpoint_port}"
        self.args.setdefault('hostHeader', host)
        self.endpoint_ip = endpoint_ip
        self.endpoint_port = endpoint_port

        logger.info(
            f"[wstunnel] Setting endpoint to: {self.server}")
        logger.info(
            f"[wstunnel] Setting host header to: {self.args['hostHeader']}")

        # Parse Listening Port
        local_server = self.args.get(
            'localToRemote',
            self.args.get('L',
                          self.args.get("dynamicToRemote",
                                        self.args.get('D')
                                        )))

        if local_server == None:
            logger.fatal(
                "[wstunnel] Local listening server is not set, expected either ('localToRemote', 'L', 'dynamicToRemote', 'D')")
            sys.exit(1)

        local_server = local_server.split(":")

        if len(local_server) == 1 or len(local_server) == 3:
            listen_port = local_server[0]
            listen_ip = '0.0.0.0'
        else:
            listen_port = local_server[1]
            listen_ip = local_server[0]

        self.listen_port = listen_port
        self.listen_ip = listen_ip

        logger.info(
            f"[wstunnel] listening on: {listen_ip}:{listen_port}")

    def _lookup_host(self, host: str):
        logger.info(f"[wstunnel] Looking up DNS / Validating IP for: '{host}'")

        if not os.path.exists("dns.json"):
            with open('dns.json', 'w') as f:
                f.write(r"{}")

        with open("dns.json", 'r+') as f:
            txt = f.read()
            f.seek(0)

            if txt == '':
                dns_json = {}
            else:
                dns_json = json.loads(txt)

            try:
                ip = socket.gethostbyname(host)
                dns_json.update({host: ip})

            except:
                logger.warning(
                    f"[wstunnel] DNS Lookup: Failed! Looking up cached entries for '{host}'")
                ip = dns_json.get(host)

                if ip == None:
                    logger.critical(
                        f"[wstunnel] DNS Lookup: Unable to automatically determine ip for '{host}'. To resolve,")
                    logger.critical(
                        f'[wstunnel] 1) Edit the server/hostHeader with ip address of {host} OR')
                    logger.critical(
                        '[wstunnel] 2) Create a dns.json file with the following content: \'{"{}":"123.4.5.6"}\''.format(host))
                    sys.exit(1)

            json.dump(dns_json, f)
            return ip

    def start(self):
        logger.info("[wstunnel] Starting wstunnel...")
        self.args = config['wstunnel']

        wst_args = [self.exec_path]
        wst_host = self.server
        for i in self.args.keys():

            flag = '-' if len(i) == 1 else '--'

            if isinstance(self.args[i], bool):
                if self.args[i] == True:
                    wst_args.append(f"{flag}{i}")
            else:
                flag = '-' if len(i) == 1 else '--'
                wst_args.append(f"{flag}{i}={self.args[i]}")

        wst_args.append(wst_host)
        logger.debug(wst_args)

        self.process = subprocess.Popen(wst_args, stdout=subprocess.PIPE)
        time.sleep(0.1)
        if self.process.poll() == None:        
            logger.info("[wstunnel] Started wstunnel!")
            return True
        else:
            logger.critical("[wstunnel] Unable to start wstunnel.")
            return False

    def stop(self):
        if self.process != None:
            logger.info("[wstunnel] Stopping...")
            self.process.kill()
            time.sleep(1)
            logger.info("[wstunnel] Stopped!")

    def restart(self):
        logger.info("[wstunnel] Restarting...")
        self.stop()
        self.start()

    def cleanup(self):
        self.stop()


class Wireguard:

    def __init__(self, gconfig, wst: WStunnel) -> None:
        self.tmp_dir = tempfile.mkdtemp()
        self.os = platform.system().lower()

        try:
            self.exec_path = gconfig["app"]["wireguard_path"]
        except KeyError:
            if self.os == 'windows':
                logger.info("[wireguard] 'wireguard_path' key is not set. Using default wireguard path at 'C:\Program Files\WireGuard\wireguard.exe'")
                self.exec_path = "C:\Program Files\WireGuard\wireguard.exe"
            
            elif self.os == 'linux':
                logger.info("[wireguard] 'wireguard_path' key is not set. Using default wireguard path at '/usr/bin/wg-quick'")
                self.exec_path = "/usr/bin/wg-quick"
            
            else:
                logger.critical(f"[wireguard] Unknown/Unsupported OS: '{self.os}', please manually set 'wireguard_path' key under 'app' section")
                sys.exit(1)
                
        logger.info("[wireguard] Loading config...")

        if gconfig['wireguard'].get('path'):

            if gconfig['wireguard'].get('str') != None:
                logger.warning(
                    "[wireguard] 'path' is set. The 'str' is ignored")

            with open(gconfig['wireguard']['path']) as f:
                logger.info(
                    f"[wireguard] Using conf file at: {gconfig['wireguard']['path']}")

                wg_str = f.read()

        else:
            logger.info(f"[wireguard] Using conf str")
            wg_str = gconfig['wireguard']['str']

        str_hash = hashlib.md5(wg_str.encode()).hexdigest()
        self.tmp_conf = os.path.join(
            self.tmp_dir,
            f'wg-wst-{str_hash[0:8]}.conf'
        )

        logger.debug(f"[wireguard] Creating temporary conf at {self.tmp_conf}")

        with open(self.tmp_conf, 'w') as f:
            f.write(wg_str)

        wg_config = wgconfig.WGConfig(self.tmp_conf)
        wg_config.read_file()

        allowed_ips = []
        peer_id = list(wg_config.peers.keys())[0]

        logger.info(
            f"[wireguard] Allowing outgoing connection to {wst.endpoint_ip}")

        for ips in wg_config.peers[peer_id]["AllowedIPs"]:

            if ips == "::/0" and self.os == 'windows':
                logger.info(
                    "[wireguard] OS == windows, skipping AllowedIPs '::/0'")
                continue

            try:
                net1 = ipaddress.ip_network(ips)
                net2 = ipaddress.ip_network(wst.endpoint_ip + "/32")
                allowed_ips.extend(
                    map(str, net1.address_exclude(net2))
                )
            except (TypeError, ValueError) as e:
                logger.warning(
                    f"[wireguard] {e} - Appending {net1} to AllowedIPs anyways")
                allowed_ips.append(ips)

        if self.os == 'windows':
            logger.info(
                "[wireguard] OS == windows, adding ['::/1','8000::/1'] to AllowedIPs")
            allowed_ips.extend(["::/1", "8000::/1"])

        logger.debug(allowed_ips)

        allowed_ips = ", ".join(set(allowed_ips))
        wg_config.del_attr(peer_id, "AllowedIPs")
        wg_config.add_attr(peer_id, "AllowedIPs", allowed_ips)

        if wst.listen_ip == '0.0.0.0':
            listen_ip = '127.0.0.1'

        logger.info(
            f"[wireguard] Changing endpoint to {listen_ip}:{wst.listen_port}")
        wg_config.del_attr(peer_id, "Endpoint")
        wg_config.add_attr(peer_id, "Endpoint",
                           f"{listen_ip}:{wst.listen_port}")

        wg_config.write_file(self.tmp_conf)

        self.wg_config = wg_config
        self.wst = wst
        self.started = False
        self.interface = os.path.basename(self.tmp_conf).replace('.conf', '')

    def remove_orphan_iface(self):
        for i in psutil.net_if_addrs().keys():
            logger.debug(f"{i} == {self.interface}: {i == self.interface}")

            if i == self.interface:
                logger.warning(
                    f"[wireguard] The interface '{self.interface}' exist this may be due to improperly stopped program or another instance is running. Attempting automatic removal")
                self.stop()

            elif i.startswith('wg-wst'):
                if self.os == 'windows':
                    logger.warning(
                        f"[wireguard] Found orphan '{self.interface}' interface attempting automatic removal...")
                    subprocess.run([
                        self.exec_path, '/uninstalltunnelservice', i], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                else:
                    logger.warning(
                        f"[wireguard] Unable to automatically remove wireguard interface:{i}")

        time.sleep(3)

    def start(self):

        if not ("L" in self.wst.args or "localToRemote" in self.wst.args):
            logger.fatal(
                "[wireguard] Unable to start wireguard. wstunnel must be started in 'L' or 'localToRemote' mode")
            sys.exit(1)

        if not ('udp' in self.wst.args or 'U' in self.wst.args):
            logger.fatal(
                "[wireguard] Unable to start wireguard. wstunnel must be started in 'udp' or 'U' mode")
            sys.exit(1)

        logger.info(f"[wireguard] Starting {self.interface}...")

        self.remove_orphan_iface()

        if self.os == 'windows':
            action = "/installtunnelservice"
        else:
            action = 'up'

        status = subprocess.run([
            self.exec_path,
            action,
            self.tmp_conf
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if status.returncode == 0:
            logger.info("[wireguard] Started wireguard!")
        else:
            logger.critical(
                f"[wireguard] Unable to start. Program return status code of: {status.returncode}")
            sys.exit(status.returncode)

        self.started = True if status.returncode == 0 else False
        return self.started

    def stop(self):
        logger.info(f"[wireguard] Stopping {self.interface}...")

        if self.os == 'windows':
            action = "/uninstalltunnelservice"
            path = self.interface
        else:
            action = 'down'
            path = self.tmp_conf

        status = subprocess.run([
            self.exec_path,
            action,
            path
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if status.returncode == 0:
            logger.info("[wireguard] Stopped!")
        else:
            logger.critical(
                f"[wireguard] Unable to stop. Program return status code of: {status.returncode}")

        self.started = True if status == 0 else False
        return self.started

    def cleanup(self):
        if self.started:
            self.stop()

        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)

    def save(self):
        shutil.copyfile(self.tmp_conf, self.interface + ".conf")

    def __del__(self):
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)


def elevate_user():
    user_os = platform.system().lower()
    logger.info("[app] Elevating to superuser / admin")
    logger.debug(f"[app] Detected OS: {user_os}")

    if user_os == 'windows':
        if not ctypes.windll.shell32.IsUserAnAdmin():
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)

    elif user_os == 'linux':
        if os.geteuid() != 0:
            os.system("sudo echo")

    else:
        logger.fatal("[app] Unsupported Platform")
        sys.exit(1)


def get_public_ip(timeout=5):
    try:
        res = requests.get("https://api.ipify.org", timeout=timeout)
        res.raise_for_status()

        return res.text

    except Exception as e:
        logger.debug(f"[app] Unable to fetch Public IP")
        logger.debug(e)
        return None


def healthcheck_ip(old_ip, sleep=5, max_it=5):

    for _ in range(max_it):
        time.sleep(sleep)
        new_ip = get_public_ip(1)

        if new_ip == None:
            logger.warning(
                f"[app] Health Check IP: Failed! Unable to fetch Public IP. Your traffic may not be tunneled!")

            continue

        elif old_ip == None and new_ip != None:
            logger.warning(
                f"[app] Health Check IP: Unknown Status! Unable to compare old_ip:{old_ip} with new_ip:{new_ip}. Your traffic may not be tunneled!")

            return True

        elif old_ip == new_ip:
            logger.warning(
                f"[app] Health Check IP: Failed! Your new_ip:{new_ip} = old_ip:{old_ip}")

            continue

        else:
            logger.info(
                f"[app] Health Check IP: Success! Your new Public IP is: {new_ip}")

            return True

    logger.warning(
        f"[app] Health Check IP: Max iteration reached! Discontinuing IP health check.")

    return False


def healthcheck_wst(wstunnel: WStunnel, interval=60, restart_wstunnel=True):

    while True:

        if interval != 0:
            time.sleep(interval)

            servers = [wstunnel.endpoint_ip, '1.1.1.1', '8.8.8.8']
            flag = '-n' if platform.system().lower() == 'windows' else '-c'

            for s in servers:
                res = subprocess.call(
                    ["ping", flag, '1', s], stdout=subprocess.PIPE)
                
                if res == 0:
                    logger.debug(f"[app] Health Check Ping: Success! Server: {s}")
                    break
            
            if res != 0:
                logger.warning(
                    f"[app] Health Check Ping: Failed! Unable to ping {servers}")

                if restart_wstunnel:
                    logger.warning(
                        f"[app] Health Check Ping: Restarting wstunnel...")

                    wstunnel.restart()
        else:
            time.sleep(9999)


# Global !!!
processes = []


@atexit.register
def cleanup():
    s1 = signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    logger.info("[app] Cleaning Up...")
    for p in processes:
        p.cleanup()

    logger.info("[app] Cleanup Complete!")
    logger.info(
        "[app] Exiting in 10s. Press CTRL + C to stop, spam it to exit now")

    try:
        signal.signal(signal.SIGINT, s1)
        time.sleep(10)
    except:
        try:
            input("***** Press Enter or CTRL + C to Exit *****")
        except:
            pass


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
    logger.info("[app] Loading app config...")

    with open(args.config) as f:
        config = yaml.full_load(f)

    elevate_user()

    try:
        wstunnel = WStunnel(config)
        wireguard = Wireguard(config, wstunnel)

        if args.clean == True:
            logger.info(
                "[app] --clean is set, attempting removal of orphaned interface")
            wireguard.remove_orphan_iface()
            sys.exit(0)

        logger.info("[app] Fetching current Public IP...")
        
        old_ip = get_public_ip(1) if config['app']['healthcheck_ip_tries'] != 0 else None

        if config['app']['start_wireguard'] == True:

            if wireguard.start() == True:
                processes.append(wireguard)

        if config['app']['start_wstunnel'] == True:

            if wstunnel.start() == True:
                processes.append(wstunnel)

        if config['app']['export_wireguard_conf'] == True:
            wireguard.save()

        logger.info(f"[app] Press CTRL + C to exit")

        healthcheck_ip(old_ip, max_it=config['app']['healthcheck_ip_tries'])
        healthcheck_wst(wstunnel, config['app']['healthcheck_wst_interval'])

    except (KeyboardInterrupt, SystemExit):
        pass

    except:
        logger.critical("[app] Caught an exception. exiting...", exc_info=True)
