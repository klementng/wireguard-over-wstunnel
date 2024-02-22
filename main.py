#!/usr/bin/python3
import argparse
import threading
import logging
import platform
import sys
import time

import safe_exit
import yaml

import helper
from core import Wireguard, WStunnel
from gui import CoreGUI

logging.basicConfig(
    format="%(levelname)s - %(name)s - %(message)s",
)

active_processes = []


def main(args, stop_event: None | threading.Event = None):
    log = logging.getLogger("main")

    with open(args.config, encoding="utf-8") as f:
        log.info("Loading 'app' config...")
        config = yaml.safe_load(f)

    log.info("Detected OS: %s", platform.system())

    wstunnel = WStunnel(config)
    wireguard = Wireguard(config, wstunnel)

    if config["app"].get("export_wireguard_conf") is True:
        wireguard.save()

    if args.clean is True:
        log.info("--clean is set, attempting removal of orphaned interface")
        wireguard.remove_orphan_iface()
        sys.exit(0)

    log.info("Fetching current Public IP...")

    old_ip = (
        helper.get_public_ip(1)
        if config["app"].get("healthcheck_ip_tries", 0) != 0
        else None
    )

    if wstunnel.start() is True:
        active_processes.append(wstunnel)
    else:
        sys.exit(1)

    if wireguard.start() is True:
        active_processes.append(wireguard)
    else:
        sys.exit(1)

    time.sleep(3)
    for i in range(config["app"].get("healthcheck_ip_tries", 0)):
        if helper.healthcheck_ip(old_ip):
            break
        if isinstance(stop_event, threading.Event) and stop_event.is_set():
            break
        time.sleep(3)

    else:
        log.warning("Healthcheck IP - Max iteration reached, discontinuing...")

    log.info("Press CTRL + C to exit or GUI button to exit")

    while True:
        if stop_event is None:
            time.sleep(9999)
        else:
            if stop_event.is_set():
                break
            time.sleep(1)

@safe_exit.register
def cleanup():
    for p in active_processes:
        p.cleanup()

if __name__ == "__main__":
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
        help="start with no gui interface",
        action="store_true",
    )
    parser.add_argument("--log_level", help="set logging level", default="INFO")
    args = parser.parse_args()

    logging.root.setLevel(args.log_level)

    helper.elevate_user()

    try:

        if args.nogui is False:
            gui = CoreGUI(helper.get_assets_path("assets/icon.png"))

            stop_event = threading.Event()
            thread = threading.Thread(target=main, args=[args, stop_event])

            gui.geometry("1280x720")
            gui.title("Wireguard over wstunnel")
            gui.after(1000, thread.start)

            gui.mainloop()
            stop_event.set()

        else:
            main(args)

    except (KeyboardInterrupt, SystemExit):
        pass

    except Exception:
        logging.critical("Caught an exception. exiting...", exc_info=True)
