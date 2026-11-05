import os
import logging
import coloredlogs

from logging import StreamHandler
from typing import Optional, Iterable
from logging.handlers import RotatingFileHandler


class LevelFilter(logging.Filter):
    """ """

    def __init__(self, allowed_levels: Iterable[int]) -> None:
        """ """

        super().__init__()
        self.allowed_levels = set(allowed_levels)

    def filter(self, record: logging.LogRecord) -> bool:
        """ """

        return record.levelno in self.allowed_levels


class RecordLog:
    """ """

    def __init__(
        self,
        name: str,
        log_dir: Optional[str] = None,
        file_level: int = logging.DEBUG,
        console_level: int = logging.INFO,
        console_levels: Optional[Iterable[int]] = None,
    ):
        """ """

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        if self.logger.hasHandlers():
            for handler in self.logger.handlers[:]:
                handler.close()

                self.logger.removeHandler(handler)

        self._setup(log_dir, file_level, console_level, console_levels)

    def _setup(self, log_dir, file_level, console_level, console_levels) -> None:
        """ """

        log_path = self._get_log_path(log_dir)

        file_handler = self._create_file_handler(log_path, file_level)
        self.logger.addHandler(file_handler)

        console_handler = self._create_console_handler(console_level, console_levels)
        self.logger.addHandler(console_handler)

    def _get_log_path(self, log_dir: Optional[str]) -> str:
        """ """

        if log_dir is None:
            log_dir = os.path.join(os.getcwd(), "logs")

        os.makedirs(log_dir, exist_ok=True)

        return os.path.join(log_dir, "app.log")

    def _create_file_handler(self, log_path: str, level: int) -> RotatingFileHandler:
        """ """

        handler = RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        handler.setLevel(level)

        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s "
            "(%(filename)s:%(lineno)d)"
        )
        handler.setFormatter(formatter)

        return handler

    def _create_console_handler(
        self, level: int, levels: Optional[Iterable[int]]
    ) -> StreamHandler:
        """ """

        handler = logging.StreamHandler()
        handler.setLevel(level)

        if levels is not None:
            handler.addFilter(LevelFilter(levels))

        formatter = coloredlogs.ColoredFormatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            level_styles=self._level_styles(),
        )

        handler.setFormatter(formatter)

        return handler

    def _level_styles(self) -> dict:
        """ """

        return {
            "debug": {"color": "white", "faint": True},
            "info": {"color": "green"},
            "warning": {"color": "yellow", "bold": True},
            "error": {"color": "red", "bold": True},
            "critical": {"color": "white", "background": "red", "bold": True},
        }

    def debug(self, msg, *args, **kwargs):
        """ """

        self.logger.debug(msg, *args, stacklevel=2, **kwargs)

    def info(self, msg, *args, **kwargs):
        """ """

        self.logger.info(msg, *args, stacklevel=2, **kwargs)

    def warning(self, msg, *args, **kwargs):
        """ """

        self.logger.warning(msg, *args, stacklevel=2, **kwargs)

    def error(self, msg, *args, **kwargs):
        """ """

        self.logger.error(msg, *args, stacklevel=2, **kwargs)

    def critical(self, msg, *args, **kwargs):
        """ """

        self.logger.critical(msg, *args, stacklevel=2, **kwargs)
