#!/usr/bin/python3
import argparse
import platform

from core import (
    Application,
    ConfigError,
    clean_wireguard,
    configure_logging,
    load_config,
    require,
)
from core.logger import logger
from core.utils.system import elevate


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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        config = load_config(args.config)
        configure_logging(require(config, "app"))
    except ConfigError as e:
        logger.critical("%s", e)
        return 2

    logger.info("Detected OS: %s", platform.system())

    try:
        elevate()

        if args.clean:
            return 0 if clean_wireguard(config) else 1

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
