import ctypes
import ctypes.wintypes
import logging
import os
import platform
import socket
import sys
import threading
import subprocess
import time
import requests
import psutil
import core

logger = logging.getLogger("app")


def elevate_user():
    logger.info("Elevating to superuser / admin")

    sys_os = platform.system()

    if sys_os == "Windows":
        if not ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore
            ctypes.windll.shell32.ShellExecuteW(  # type: ignore
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0)

    elif sys_os in ["Linux", "Darwin"]:  # linux mac os
        if os.geteuid() != 0:
            logger.info("Elevating via sudo: 'sudo echo'")
            os.system("sudo echo")

    else:
        logger.critical("Unknown/Unsupported OS.")
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


def healthcheck_process(
    wireguard: core.Wireguard,
    wstunnel: core.WStunnel,
    restart_wg: bool = True,
    restart_wst: bool = True,
    log: bool = True,
):
    logger = logging.getLogger("healthcheck:state")

    wg_is_healthy = wireguard.is_running
    wst_is_healthy = wstunnel.is_running

    if log:
        if not wg_is_healthy:
            logger.critical("wireguard is not started!")

        if not wst_is_healthy:
            logger.critical("wstunnel is not started!")

    if not wg_is_healthy and restart_wg:
        logger.info("Attempting restart of wireguard...")
        wireguard.restart()

    if not wst_is_healthy and restart_wst:
        logger.info("Attempting restart of wstunnel...")
        wstunnel.restart()

    return wg_is_healthy and wst_is_healthy


def healthcheck_ping(
    wireguard: core.Wireguard,
    wstunnel: core.WStunnel,
    restart_wg: bool = True,
    restart_wst: bool = True,
):
    log = logging.getLogger("healthcheck:ping")
    servers = [wstunnel.endpoint_ip, "1.1.1.1"]
    flag = "-n" if platform.system() == "Windows" else "-c"

    for s in servers:
        res = subprocess.call(["ping", flag, "1", s], stdout=subprocess.PIPE)

        if res == 0:
            log.debug(f"Success! Server: {s}")
            break

    if res != 0:
        log.warning(f"Failed! Unable to ping {servers}")

        if restart_wg is True:
            log.warning("Restarting wstunnel")
            wireguard.restart()

        if restart_wst is True:
            log.warning("Restarting wstunnel")
            wstunnel.restart()


def healthcheck_ip(old_ip):
    log = logging.getLogger("healthcheck:ip")
    new_ip = get_public_ip(1)

    if new_ip is None:
        log.warning(
            "Failed! Unable to fetch Public IP. Your traffic may not be tunneled!"
        )

        return False

    elif old_ip is None and new_ip is not None:
        log.warning(
            "Unknown Status!"
            + f"Unable to compare old_ip: {old_ip} with new_ip: {new_ip} Your traffic may not be tunneled!"  # noqa
        )

        return True

    elif old_ip == new_ip:
        log.warning(
            f"Failed! Your new_ip: {new_ip} = old_ip: {old_ip}. Your traffic may not be tunneled!"
        )

        return False

    else:
        log.info(f"Success! Your new Public IP is: {new_ip}")

        return True


def get_assets_path(rel_path):
    try:
        base_path = sys._MEIPASS  # type: ignore
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, rel_path)


def run_as_thread(target, args=(), kwargs=None, daemon=True, *a, **kw):

    def wrap():
        t = threading.Thread(
            target=target, args=args, kwargs=kwargs, daemon=daemon, *a, **kw
        )
        t.start()

    return wrap
