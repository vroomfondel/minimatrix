"""Tests for minimatrix.__init__ — version and logging setup."""

from __future__ import annotations

import minimatrix
from minimatrix import _loguru_skiplog_filter


def test_version_is_string() -> None:
    assert isinstance(minimatrix.__version__, str)
    assert len(minimatrix.__version__) > 0


def test_loguru_skiplog_filter_passes_normal() -> None:
    record: dict = {"extra": {"skiplog": False}}  # type: ignore[type-arg]
    assert _loguru_skiplog_filter(record) is True


def test_loguru_skiplog_filter_blocks_skiplog() -> None:
    record: dict = {"extra": {"skiplog": True}}  # type: ignore[type-arg]
    assert _loguru_skiplog_filter(record) is False


def test_loguru_skiplog_filter_missing_extra() -> None:
    record: dict = {}  # type: ignore[type-arg]
    assert _loguru_skiplog_filter(record) is True


def test_loguru_skiplog_filter_missing_skiplog_key() -> None:
    record: dict = {"extra": {}}  # type: ignore[type-arg]
    assert _loguru_skiplog_filter(record) is True


def test_configure_logging_runs_without_error() -> None:
    """Smoke test — configure_logging() should not raise."""
    minimatrix.configure_logging()
