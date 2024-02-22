import ctypes
import ctypes.wintypes
import logging
import os
import platform
import sys
import time
import requests
import psutil

import core

logger = logging.getLogger("app")


def elevate_user():
    logger.info("Elevating to superuser / admin")

    if platform.system().lower() == "windows":
        if not ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore
            ctypes.windll.shell32.ShellExecuteW(  # type: ignore
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0)

    elif platform.system().lower() == "linux":
        if os.geteuid() != 0:
            os.system("sudo echo")

    else:
        if os.geteuid() != 0:
            logger.critical("Unknown/Unsupported OS. Please program run as superuser")
            sys.exit(1)


def get_public_ip(timeout=3):
    try:
        res = requests.get("https://api.ipify.org", timeout=timeout)
        res.raise_for_status()

        return res.text

    except Exception as e:
        logger.debug("Unable to fetch Public IP")
        logger.debug(e)
        return None


def healthcheck(wireguard: core.Wireguard, wstunnel: core.WStunnel, restart=True):

    wg = wireguard.iface_name in list(psutil.net_if_addrs().keys())

    if wstunnel.process is not None:
        ws = wstunnel.process.poll() is None

    if restart:
        if not ws:
            wstunnel.start()
        if not wg:
            wireguard.start()

        time.sleep(1)

        wg = wireguard.iface_name in list(psutil.net_if_addrs().keys())
        if wstunnel.process is not None:
            ws = wstunnel.process.poll() is None

    return wg and ws


def healthcheck_ip(old_ip):
    new_ip = get_public_ip(1)

    if new_ip is None:
        logger.warning(
            "Health Check IP: Failed! Unable to fetch Public IP. Your traffic may not be tunneled!"
        )

        return False

    elif old_ip is None and new_ip is not None:
        logger.warning(
            "Health Check IP: Unknown Status!"
            + f"Unable to compare old_ip: {old_ip} with new_ip: {new_ip} Your traffic may not be tunneled!" # noqa
        )

        return True

    elif old_ip == new_ip:
        logger.warning(
            f"Health Check IP: Failed! Your new_ip: {new_ip} = old_ip: {old_ip}. Your traffic may not be tunneled!"
        )

        return False

    else:
        logger.info(f"Health Check IP: Success! Your new Public IP is: {new_ip}")

        return True


def get_assets_path(rel_path):
    try:
        base_path = sys._MEIPASS  # type: ignore
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, rel_path)
