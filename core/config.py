import logging
from logging.handlers import RotatingFileHandler

import yaml

from .exception import ConfigError
from .logger import logger

LOGGING_FORMAT = "%(asctime)s - %(levelname)s - %(name)s - %(message)s"


def require(mapping: dict, key: str, section: str = "config"):
    if not isinstance(mapping, dict) or key not in mapping:
        raise ConfigError(f"Missing required config key: {section}.{key}")
    return mapping[key]


def load_config(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as file:
            data = yaml.safe_load(file)
    except OSError as e:
        raise ConfigError(f"Unable to read config file '{path}': {e}") from e
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in config file '{path}': {e}") from e

    if not isinstance(data, dict):
        raise ConfigError(f"Config file '{path}' must contain a YAML mapping")

    return data


def configure_logging(app_config: dict, fmt: str = LOGGING_FORMAT) -> logging.Logger:
    logging_config = require(app_config, "logging", "app")
    if not isinstance(logging_config, dict):
        raise ConfigError("app.logging must be a mapping")

    level = logging_config.get("level", "INFO")
    if isinstance(level, str):
        level = level.upper()
        level_names = logging.getLevelNamesMapping()
        if level not in level_names:
            raise ConfigError(f"Invalid logging level: {level}")
        level = level_names[level]
    elif not isinstance(level, int):
        raise ConfigError(f"Invalid logging level: {level!r}")

    try:
        logging.basicConfig(format=fmt, level=level)
    except ValueError as e:
        raise ConfigError(f"Invalid logging level: {level}") from e

    # basicConfig is a no-op if handlers are already installed; apply it anyway.
    logging.root.setLevel(level)

    filename = logging_config.get("file")
    if filename:
        try:
            handler = RotatingFileHandler(
                filename,
                maxBytes=1_000_000,
                backupCount=3,
                encoding="utf-8",
            )
        except OSError as e:
            raise ConfigError(f"Unable to open log file '{filename}': {e}") from e

        handler.setFormatter(logging.Formatter(fmt))
        logging.root.addHandler(handler)

    return logger
