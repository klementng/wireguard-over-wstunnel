#!/usr/bin/python3
import argparse
from datetime import timedelta
import datetime
import threading
import logging
import platform
import sys
import time
import tkinter as tk

import safe_exit
import yaml

import helper
from core import Wireguard, WStunnel
from gui import CoreGUI

logging.basicConfig(
    format="%(levelname)s - %(name)s - %(message)s",
)

active_processes = []


def main(
    args, stop_event: None | threading.Event = None, root_win: CoreGUI | None = None
):
    log = logging.getLogger("main")

    with open(args.config, encoding="utf-8") as f:
        log.info("Loading 'app' config...")
        config = yaml.safe_load(f)

    log.info("Detected OS: %s", platform.system())

    wstunnel = WStunnel(config)
    wireguard = Wireguard(config, wstunnel)

    if args.export is True:
        log.info("--export is set, saving wireguard configuration to current directory")
        wireguard.save()
        sys.exit(0)

    if args.clean is True:
        log.info("--clean is set, attempting removal of orphaned interface")
        wireguard.remove_orphan_iface()
        sys.exit(0)

    wireguard.remove_orphan_iface()

    log.info("Fetching current Public IP...")

    old_ip = (
        helper.get_public_ip(1)
        if config["app"].get("healthcheck_ip_tries", 0) != 0
        else None
    )

    attempts = 0
    while not helper.healthcheck_process(
        wireguard, wstunnel, restart_wg=False, restart_wst=False, log=False
    ):
        attempts += 1

        if isinstance(stop_event, threading.Event) and stop_event.is_set():
            break
        if attempts > 3:
            log.critical("Failed to start required processes in 3 tries. Aborting...")
            log.critical(
                "Ensure required ports / ip are free and available for binding."
            )
            log.critical("Close any hanging wstunnel instance using task manager")
            sys.exit(1)

        if not wireguard.is_running:
            if wireguard.start():
                active_processes.append(wireguard)

        if not wstunnel.is_running:
            if wstunnel.start():
                active_processes.append(wstunnel)

        time.sleep(3)

    if isinstance(root_win, CoreGUI):
        tk.Button(
            root_win,
            text="Run healthcheck ip",
            command=helper.run_as_thread(helper.healthcheck_ip, args=[old_ip]),
        ).pack(in_=root_win.toolbar, side="left")

        tk.Button(
            root_win,
            text="Restart wstunnel",
            command=helper.run_as_thread(wstunnel.restart),
        ).pack(in_=root_win.toolbar, side="left")

        tk.Button(
            root_win,
            text="Restart wireguard",
            command=helper.run_as_thread(wireguard.restart),
        ).pack(in_=root_win.toolbar, side="left")

    hc: dict = config["app"].get("healthcheck", {})
    hc.setdefault(
        "healthcheck",
        {
            "ip": {"enabled": True, "tries": 3},
            "ping": {
                "enabled": True,
                "interval": 10,
                "restart": {"wstunnel": True, "wireguard": False},
            },
            "process": {
                "enabled": True,
                "interval": 10,
                "restart": {"wstunnel": True, "wireguard": True},
            },
        },
    )

    if hc["ip"]["enabled"] is True:
        for i in hc["ip"]["tries"]:
            if isinstance(stop_event, threading.Event) and stop_event.is_set():
                break

            if helper.healthcheck_ip(old_ip):
                break

            time.sleep(3)

        else:
            log.warning("Healthcheck IP - Max iteration reached, discontinuing...")

    log.info("Press CTRL + C to exit or GUI button to exit")

    time_process = datetime.datetime.now()
    time_ping = datetime.datetime.now()

    while True:
        if isinstance(stop_event, threading.Event) and stop_event.is_set():
            break

        if hc["process"]["enabled"]:
            exec_time = time_process + datetime.timedelta(
                seconds=hc["process"]["interval"]
            )

            if datetime.datetime.now() > exec_time:
                time_process = datetime.datetime.now()
                helper.healthcheck_process(
                    wireguard,
                    wstunnel,
                    restart_wg=hc["process"]["restart"]["wireguard"],
                    restart_wst=hc["process"]["restart"]["wstunnel"],
                )

        if hc["ping"]["enabled"]:
            exec_time = time_ping + datetime.timedelta(seconds=hc["ping"]["interval"])
            if datetime.datetime.now() > exec_time:
                time_ping = datetime.datetime.now()

                helper.healthcheck_ping(
                    wireguard,
                    wstunnel,
                    restart_wg=hc["ping"]["restart"]["wireguard"],
                    restart_wst=hc["ping"]["restart"]["wstunnel"],
                )

        time.sleep(1)


@safe_exit.register
def cleanup():
    global active_processes

    for p in active_processes:
        p.cleanup()

    active_processes = []


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
        "--export",
        help="export wireguard config and exit",
        action="store_true",
    )
    parser.add_argument(
        "--nogui",
        help="start with no gui",
        action="store_true",
    )

    parser.add_argument("--log_level", help="set logging level", default="INFO")
    args = parser.parse_args()

    logging.root.setLevel(args.log_level)

    helper.elevate_user()

    try:

        if args.nogui is False:
            root = CoreGUI(helper.get_assets_path("assets/icon.png"))

            stop_event = threading.Event()
            thread = threading.Thread(
                target=main, args=[args, stop_event, root], daemon=True
            )

            root.geometry("1280x720")
            root.title("Wireguard over wstunnel")
            root.after(1000, thread.start)

            root.mainloop()
            stop_event.set()

        else:
            main(args)

    except (KeyboardInterrupt, SystemExit):
        pass

    except Exception:
        logging.critical("Caught an exception. exiting...", exc_info=True)

    finally:
        cleanup()
