#!/usr/bin/python3
import argparse
import ctypes
import logging
import os
import platform
import sys
import time

import yaml

from core import (
    HealthCheckConfig,
    HealthCheckIP,
    HealthCheckPing,
    HealthCheckState,
    ProcessManager,
    WireguardConfig,
    WireguardProcess,
    WstunnelConfig,
    WstunnelProcess,
)

from gui import Interface


LOGGING_FORMAT = "%(levelname)s - %(name)s - %(message)s"

logging.basicConfig(
    format=LOGGING_FORMAT,
)


logger = logging.getLogger("main")


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
        if os.geteuid() != 0:  # type: ignore
            logger.info("Elevating via sudo: 'sudo echo'")
            os.system("sudo echo")

    else:
        logger.critical("Unknown/Unsupported OS.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Wireguard over wstunnel")
    parser.add_argument(
        "--config", "-c", help="path to program config", default="./config.yml"
    )
    parser.add_argument(
        "--clean",
        help="clean wireguard tunnel that are not properly stopped",
        action="store_true",
    )
    parser.add_argument(
        "--nogui",
        help="start with no gui",
        action="store_true",
    )

    args = parser.parse_args()

    logger.info("Detected OS: %s", platform.system())
    with open(args.config, encoding="utf-8") as f:
        logger.info("Loading config...")
        config = yaml.safe_load(f)

    app_config = config["app"]

    logging.root.setLevel(app_config["logging"]["level"])
    if app_config["logging"]["file"] is not None:
        fn = logging.FileHandler(app_config["logging"]["file"])
        fn.setFormatter(logging.Formatter(LOGGING_FORMAT))
        logging.root.addHandler(fn)

    wst_config = WstunnelConfig.init(config["wstunnel"])
    wg_config = WireguardConfig.init(config["wireguard"], wst_config)
    hc_config = config["healthcheck"]

    wst = WstunnelProcess(wst_config)
    wg = WireguardProcess(wg_config)

    hc_ping = HealthCheckPing(HealthCheckConfig.init(hc_config["ping"]), wg, wst)
    hc_state = HealthCheckState(HealthCheckConfig.init(hc_config["state"]), wg, wst)
    hc_ip = HealthCheckIP(HealthCheckConfig.init(hc_config["ip"]), wg, wst)

    if args.clean is True:
        wg.reset()
        return

    else:
        elevate_user()

        manager = ProcessManager()
        manager.add(wst)
        manager.add(wg)
        manager.add(hc_ping)
        manager.add(hc_state)
        manager.add(hc_ip)
        try:
            if args.nogui:
                manager.start()
            else:
                gui = Interface(manager)
                gui.mainloop()
        finally:
            manager.stop()


if __name__ == "__main__":

    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        pass

    except Exception:
        logging.critical("Caught an exception. exiting...", exc_info=True)

    finally:
        time.sleep(1)
