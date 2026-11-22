#!/usr/bin/env python3
import argparse
import logging
import platform
import sys

from core import (
    Application,
    ConfigError,
    clean_wireguard,
    configure_logging,
    load_config,
    require,
)
from core.config import LOGGING_FORMAT
from core.exception import ExecutableNotFoundError
from core.logger import logger
from core.utils.system import elevate, owns_windows_console


def _default_gui() -> bool:
    """Default to tray GUI when double-clicked as a frozen Windows executable."""
    return getattr(sys, "frozen", False) and owns_windows_console()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Wireguard over wstunnel",
        epilog="Run the program with --clean to remove leftover wg-wst-* interfaces.",
    )
    parser.add_argument(
        "--config", "-c", help="path to program config", default="./config.yml"
    )
    parser.add_argument(
        "--clean",
        help="clean wireguard tunnels that were not properly stopped",
        action="store_true",
    )
    parser.add_argument(
        "--gui",
        help="start with the system tray GUI (default when double-clicked on Windows)",
        action=argparse.BooleanOptionalAction,
        default=_default_gui(),
    )
    parser.add_argument(
        "--auto-connect",
        help="connect automatically when the tray GUI starts",
        action="store_true",
    )
    parser.add_argument(
        "--detached",
        help="detach and run the tray GUI in the background",
        action="store_true",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    use_gui = args.gui and not args.clean

    config: dict | None = None
    startup_error: str | None = None

    try:
        config = load_config(args.config)
        configure_logging(require(config, "app"))
    except ConfigError as e:
        if not use_gui:
            logger.critical("%s", e)
            return 2
        logging.basicConfig(format=LOGGING_FORMAT, level=logging.INFO)
        logger.error("Invalid config: %s", e)
        startup_error = str(e)

    logger.info("Detected OS: %s", platform.system())

    try:
        elevate()

        if args.clean:
            if config is None:
                return 2
            return 0 if clean_wireguard(config) else 1

        if use_gui:
            from gui import TrayApp, detach_to_background

            if args.detached:
                detach_to_background(argv)

            app: Application | None = None
            if config is not None:
                try:
                    app = Application(config)
                except (ConfigError, ExecutableNotFoundError) as e:
                    logger.error("Invalid config: %s", e)
                    startup_error = str(e)

            TrayApp(
                app,
                config=config,
                config_path=args.config,
                auto_connect=args.auto_connect and app is not None,
                initial_error=startup_error,
            ).run()
            return 0

        if config is None:
            return 2

        Application(config).run()
        return 0

    except ConfigError as e:
        logger.critical("%s", e)
        return 2
    except KeyboardInterrupt:
        logger.info("Interrupted, shutting down...")
        return 0
    except Exception:
        logger.critical("Caught an exception. Exiting...", exc_info=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
