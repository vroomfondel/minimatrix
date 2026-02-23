"""Tests for minimatrix.__init__ — version and logging setup."""

from __future__ import annotations

import minimatrix
from minimatrix import _loguru_skiplog_filter


def test_version_is_string() -> None:
    """Verifies that __version__ is a non-empty string."""
    assert isinstance(minimatrix.__version__, str)
    assert len(minimatrix.__version__) > 0


def test_loguru_skiplog_filter_passes_normal() -> None:
    """Verifies that a record with skiplog=False is allowed through the filter."""
    record: dict = {"extra": {"skiplog": False}}  # type: ignore[type-arg]
    assert _loguru_skiplog_filter(record) is True


def test_loguru_skiplog_filter_blocks_skiplog() -> None:
    """Verifies that a record with skiplog=True is suppressed by the filter."""
    record: dict = {"extra": {"skiplog": True}}  # type: ignore[type-arg]
    assert _loguru_skiplog_filter(record) is False


def test_loguru_skiplog_filter_missing_extra() -> None:
    """Verifies that a record without an 'extra' key is allowed through the filter."""
    record: dict = {}  # type: ignore[type-arg]
    assert _loguru_skiplog_filter(record) is True


def test_loguru_skiplog_filter_missing_skiplog_key() -> None:
    """Verifies that a record with an 'extra' dict that has no 'skiplog' key is allowed through."""
    record: dict = {"extra": {}}  # type: ignore[type-arg]
    assert _loguru_skiplog_filter(record) is True


def test_configure_logging_runs_without_error() -> None:
    """Smoke test — configure_logging() should not raise."""
    minimatrix.configure_logging()
