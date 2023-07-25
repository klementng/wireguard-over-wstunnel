#!/usr/bin/env python3

import socket
import os
import ipaddress
import ctypes
import atexit
import subprocess
import sys
import time
import argparse
import wgconfig
import yaml
import tempfile
import logging
import shutil
import requests
import netifaces
import ctypes
import signal

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s'
)


# global variables

logger = logging.getLogger()
config = None

### defined in if __name__ == '__main__'

def configure_wstunnel():
    logger.info("Loading wstunnel config...")

    proto, host = config['wstunnel'].get('server').split("://")

    if len(host.split(':')) == 2:
        host, port = host.split(':')

    localToRemote = config['wstunnel'].get('localToRemote').split(':')

    if len(localToRemote) == 3:
        listen_port = localToRemote[0]
        listen_ip = '0.0.0.0'
    else:
        listen_port = localToRemote[1]
        listen_ip = localToRemote[0]

    endpoint_ip = socket.gethostbyname(host)

    # change server to ip / host
    config['wstunnel']['server'] = f"{proto}://{endpoint_ip}"
    config['wstunnel'].setdefault('hostHeader', host)

    logger.info(f"Setting wstunnel to listen on: {listen_ip}:{listen_port}")
    logger.info(
        f"Setting wstunnel endpoint to: {config['wstunnel']['server']}")
    logger.info(
        f"Setting wstunnel host header to: {config['wstunnel']['hostHeader']}")

    return endpoint_ip, listen_ip, listen_port


def configure_wireguard(wst_endpoint_ip, wst_local_ip, wst_local_port):
    logger.info("Loading wireguard config...")

    tmpfile = tempfile.NamedTemporaryFile(
        'w+', prefix='wg-wst-', suffix='.conf', delete=False)
    logger.debug(f"Created temporary file at {tmpfile.name}")

    if config['wireguard'].get('path'):

        if config['wireguard'].get('str') != None:
            logger.warning(
                "wireguard 'path' is set. The 'str' config is ignored")

        logger.info(f"Using wireguard file at: {config['wireguard']['path']}")
        with open(config['wireguard']['path']) as f:
            tmpfile.write(f.read())

    else:
        logger.info(f"Using wireguard config str")
        tmpfile.write(config['wireguard']['str'])

    tmpfile.close()

    wg_config = wgconfig.WGConfig(tmpfile.name)
    wg_config.read_file()

    allowed_ips = []
    peer_id = list(wg_config.peers.keys())[0]

    logger.info(f"Allowing outgoing connection to {wst_endpoint_ip}")

    for ips in wg_config.peers[peer_id]["AllowedIPs"]:
        try:
            net = ipaddress.ip_network(ips)
            allowed_ips.extend(
                map(str, net.address_exclude(
                    ipaddress.ip_network(wst_endpoint_ip + "/32")
                ))
            )
        except TypeError:
            allowed_ips.append(ips)

    allowed_ips = ", ".join(set(allowed_ips))
    wg_config.del_attr(peer_id, "AllowedIPs")
    wg_config.add_attr(peer_id, "AllowedIPs", allowed_ips)

    if wst_local_ip == '0.0.0.0':
        wst_local_ip = '127.0.0.1'

    logger.info(
        f"Changing wireguard endpoint ip to {wst_local_ip}:{wst_local_port}")
    wg_config.del_attr(peer_id, "Endpoint")
    wg_config.add_attr(peer_id, "Endpoint", f"{wst_local_ip}:{wst_local_port}")

    wg_config.write_file(tmpfile.name)

    return tmpfile, wg_config


def start_wireguard(wg_config_path):
    interface_name = os.path.basename(wg_config_path).replace('.conf', '')

    logger.info("Starting wireguard...")
    logger.info(f"Wireguard interface name: {interface_name}")

    if config['app']['os'] == 'windows':
        command = '"%s" /installtunnelservice %s' % (
            config["app"]["wireguard_path"], wg_config_path)
    else:
        command = 'sudo %s up %s' % (
            config["app"]["wireguard_path"], wg_config_path)

    logger.debug(command)
    os.system(command)


def stop_wireguard(wg_config_path):
    interface_name = os.path.basename(wg_config_path).replace('.conf', '')
    logger.info(f"Stopping wireguard interface: {interface_name}")

    if config['app']['os'] == 'windows':
        command = '"%s" /uninstalltunnelservice %s' % (
            config["app"]["wireguard_path"], interface_name)
    else:
        command = 'sudo %s down %s' % (
            config["app"]["wireguard_path"], wg_config_path)

    logger.debug(command)
    os.system(command)

    time.sleep(1)


def start_wstunnel():
    logger.info("Starting wstunnel...")
    wst_config = config['wstunnel']

    wst_args = [config['app']['wstunnel_path']]
    wst_host = wst_config.pop('server')
    for i in wst_config.keys():

        flag = '-' if len(i) == 1 else '--'

        if isinstance(wst_config[i], bool):
            if wst_config[i] == True:
                wst_args.append(f"{flag}{i}")
        else:
            flag = '-' if len(i) == 1 else '--'
            wst_args.append(f"{flag}{i}={wst_config[i]}")

    wst_args.append(wst_host)
    logger.debug(wst_args)

    return subprocess.Popen(wst_args, stdout=subprocess.PIPE)


def stop_wstunnel(process: subprocess.Popen):
    logger.info("Stopping wstunnel")
    process.kill()
    time.sleep(1)


def cleanup(tmpfile, wstunnel_process):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    if config['app']['start_wireguard'] == True:
        stop_wireguard(tmpfile.name)
    if wstunnel_process != None:
        stop_wstunnel(wstunnel_process)

    logger.info(f"Removing temp file at {tmpfile.name}")
    os.unlink(tmpfile.name)


def main():
    try:

        try:
            old_ip = requests.get("https://api.ipify.org", timeout=5)
            old_ip.raise_for_status()
            old_ip = old_ip.text
            logger.debug(f"Current old IP: {old_ip}")
        except Exception as e:
            logger.warn(
                f"Unable to get current IP. Are you connected to the internet?. Error: {e}")

        wst_endpoint_ip, wst_listen_ip, wst_listen_port = configure_wstunnel()
        tmpfile, wg_config = configure_wireguard(
            wst_endpoint_ip, wst_listen_ip, wst_listen_port)

        wst_process = None
        if config['app']['start_wireguard'] == True:
            start_wireguard(tmpfile.name)

        if config['app']['start_wstunnel'] == True:
            wst_process = start_wstunnel()

        if config['app']['export_wireguard_conf'] == True:
            shutil.copyfile(tmpfile.name, os.path.basename(tmpfile.name))

        atexit.register(cleanup, tmpfile, wst_process)

        logger.info(f"Press CTRL + C to exit")

        while True:
            time.sleep(3)

            try:
                res = requests.get("https://api.ipify.org", timeout=5)
                res.raise_for_status()

                if res.status_code == 200:
                    new_ip = res.text

                    if old_ip == new_ip:
                        logger.warning(
                            f"Health Check failed! Your new ip = old ip: {new_ip}")
                    else:
                        logger.info(f"Your Public IP is: {new_ip}")
                        break

            except Exception as e:
                logger.warning(f"Health Check failed!. Error: {e}")

        while True:
            time.sleep(100)

    except (KeyboardInterrupt, SystemExit):
        pass

    except:
        logger.critical("Caught an exception", exc_info=True)

    finally:
        try:
            time.sleep(0.5)
            input('***** Press enter to exit *****')
        except:
            pass

        logger.info(f"Exiting...")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Wireguard over wstunnel")
    parser.add_argument('--action', '-a', help="Start the program / clean wg tunnel that are not properly stopped",
                        default='start', choices=['start', 'clean'])
    parser.add_argument(
        '--config', '-c', help="Path to program config", default='./config.yml')
    args = parser.parse_args()

    logger.info("Loading app config...")

    with open(args.config) as f:
        config = yaml.full_load(f)

        logger.info("Elevating to superuser / admin")
        if config['app']['os'] == 'windows':
            if not ctypes.windll.shell32.IsUserAnAdmin():
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

        elif config['app']['os'] == 'linux':
            if os.geteuid() != 0:
                os.system("sudo echo")

        else:
            logger.fatal("Unsupported Platform")
            exit(1)

    # disconnect old connections
        if args.action == 'clean':
            if config['app']['os'] == 'windows':
                for i in netifaces.interfaces():
                    if i.startswith('wg-wst'):
                        stop_wireguard(i)
            else:
                logger.fatal("Not Supported in linux")
            input('***** Press enter to exit *****')
            exit(0)
        
        else:
            main()