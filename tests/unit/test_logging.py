"""CLI console-logging setup."""

import logging

from kolega_security_scanner.cli._logging import configure_logging

ROOT = "kolega_security_scanner"


def _reset() -> None:
    logger = logging.getLogger(ROOT)
    logger.handlers = [h for h in logger.handlers if not getattr(h, "_kolega_console", False)]


def test_default_is_info_and_single_handler():
    _reset()
    configure_logging(0)
    logger = logging.getLogger(ROOT)
    assert logger.level == logging.INFO
    consoles = [h for h in logger.handlers if getattr(h, "_kolega_console", False)]
    assert len(consoles) == 1


def test_idempotent_no_duplicate_handlers():
    _reset()
    configure_logging(0)
    configure_logging(1)
    logger = logging.getLogger(ROOT)
    consoles = [h for h in logger.handlers if getattr(h, "_kolega_console", False)]
    assert len(consoles) == 1
    assert logger.level == logging.DEBUG  # last call wins


def test_quiet_and_verbose_levels():
    _reset()
    configure_logging(-1)
    assert logging.getLogger(ROOT).level == logging.WARNING
    configure_logging(1)
    assert logging.getLogger(ROOT).level == logging.DEBUG


def test_progress_goes_to_stderr_not_stdout(capsys):
    _reset()
    configure_logging(0)
    logging.getLogger(f"{ROOT}.scanners").info("hello-progress")
    captured = capsys.readouterr()
    assert "hello-progress" in captured.err
    assert captured.out == ""
