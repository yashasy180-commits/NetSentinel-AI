import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging(app) -> None:

    log_directory = (
        Path(app.root_path)
        / "logs"
    )

    log_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_file = (
        log_directory
        / "app.log"
    )

    handler = RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )

    handler.setLevel(
        logging.INFO
    )

    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(name)s | "
            "%(message)s"
        )
    )

    app.logger.setLevel(
        logging.INFO
    )

    if not any(
        isinstance(
            existing,
            RotatingFileHandler,
        )
        and getattr(
            existing,
            "baseFilename",
            None,
        )
        == str(log_file)
        for existing
        in app.logger.handlers
    ):
        app.logger.addHandler(
            handler
        )