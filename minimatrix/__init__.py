"""minimatrix — standalone Matrix protocol CLI client with E2E encryption.

This package exposes the ``minimatrix`` console script (entry point
``minimatrix.cli:main``) and the supporting ``MatrixClientHandler`` that
wraps ``matrix-nio[e2e]`` for all Matrix protocol operations.

Logging is handled exclusively through **loguru**.  The root logger is
disabled at import time (``glogger.disable(__name__)``) so that library
consumers are not affected; the CLI entry point explicitly enables it via
``configure_logging()`` and ``glogger.enable("minimatrix")``.
"""

__version__ = "0.0.11"

import logging
import os
import sys
import types
from typing import Any, Callable, Dict

from loguru import logger as glogger


class _InterceptHandler(logging.Handler):
    """Route standard ``logging`` records into loguru.

    Installed on the root logger so that libraries using the stdlib
    ``logging`` module (e.g. ``matrix-nio``) have their output formatted
    and coloured consistently by loguru instead of printing raw to stderr.
    """

    def emit(self, record: logging.LogRecord) -> None:  # noqa: D401
        # Map stdlib level to loguru level name
        try:
            level: str | int = glogger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Walk the stack to find the frame depth outside of the logging module
        # so that loguru reports the correct caller location.
        current: types.FrameType | None = logging.currentframe()
        depth = 0
        while current is not None:
            if current.f_code.co_filename != logging.__file__:
                depth += 1
                if depth > 1:
                    break
            current = current.f_back

        glogger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


from tabulate import tabulate

glogger.disable(__name__)


def _loguru_skiplog_filter(record: dict) -> bool:  # type: ignore[type-arg]
    """Filter function to hide records with ``extra['skiplog']`` set.

    Args:
        record: A loguru log record dict.

    Returns:
        ``False`` when the record carries ``extra['skiplog'] == True``,
        suppressing it from the sink; ``True`` otherwise.
    """
    return not record.get("extra", {}).get("skiplog", False)


LOGURU_FORMAT: str = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{module}</cyan>::<cyan>{extra[classname]}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
)


def configure_logging(
    loguru_filter: Callable[[Dict[str, Any]], bool] = _loguru_skiplog_filter,
) -> None:
    """Configure a default ``loguru`` sink with a convenient format and filter.

    Removes all existing sinks, then adds a single ``sys.stderr`` sink
    using ``LOGURU_FORMAT`` and the given *loguru_filter*.  The log level
    is read from the ``LOGURU_LEVEL`` environment variable (defaulting to
    ``DEBUG``).

    Args:
        loguru_filter: A callable accepting a loguru record dict and
            returning ``True`` to keep or ``False`` to suppress the
            record.  Defaults to ``_loguru_skiplog_filter``.
    """
    os.environ["LOGURU_LEVEL"] = os.getenv("LOGURU_LEVEL", "DEBUG")
    glogger.remove()
    glogger.add(sys.stderr, level=os.getenv("LOGURU_LEVEL"), format=LOGURU_FORMAT, filter=loguru_filter)  # type: ignore[arg-type]
    glogger.configure(extra={"classname": "None", "skiplog": False})

    # Intercept stdlib logging (e.g. matrix-nio) → loguru
    logging.basicConfig(handlers=[_InterceptHandler()], level=0, force=True)


def print_banner() -> None:
    """Log a startup banner with version, build time, and project URLs.

    Renders a ``tabulate`` mixed-grid table with a Unicode box-drawing
    title row and emits it via loguru in raw mode.
    """
    startup_rows = [
        ["version", __version__],
        ["buildtime", os.environ.get("BUILDTIME", "n/a")],
        ["github", "https://github.com/vroomfondel/minimatrix"],
        ["Docker Hub", "https://hub.docker.com/r/xomoxcc/minimatrix"],
    ]
    table_str = tabulate(startup_rows, tablefmt="mixed_grid")
    lines = table_str.split("\n")
    table_width = len(lines[0])
    title = "minimatrix starting up"
    title_border = "\u250d" + "\u2501" * (table_width - 2) + "\u2511"
    title_row = "\u2502 " + title.center(table_width - 4) + " \u2502"
    separator = lines[0].replace("\u250d", "\u251d").replace("\u2511", "\u2525").replace("\u252f", "\u253f")

    glogger.opt(raw=True).info(
        "\n{}\n", title_border + "\n" + title_row + "\n" + separator + "\n" + "\n".join(lines[1:])
    )
