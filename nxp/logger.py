"""
Logger for the NXP server and client.

OS Concept: Writing to a file is a system call (write(2)) that copies bytes
from user-space into the kernel's page cache. The OS eventually flushes the
page cache to disk (write-back). Python's logging module batches small writes
and calls the underlying OS write() on each log record when the handler's
stream is unbuffered or when flush() is called.  Opening server.log with
mode='a' (append) ensures that even if the process crashes and restarts, past
log entries are not lost — the kernel sets the file-offset pointer to the end
of the file on each open() call when O_APPEND is set.
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

# Default log file lives beside this module, but can be overridden via env var.
_LOG_DIR  = os.path.dirname(os.path.abspath(__file__))
_LOG_FILE = os.environ.get("NXP_LOG_FILE", os.path.join(_LOG_DIR, "server.log"))

# Single shared format used by every handler so console and file are consistent.
_FMT = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
    """
    Return a named logger that writes to both stdout (INFO+) and a rotating
    log file (DEBUG+).

    Using a named logger (rather than the root logger) lets server, client,
    and protocol each appear under their own label in the log, making it easy
    to filter messages by component.

    Args:
        name:  logger name, e.g. "server", "client", "protocol"
        level: minimum level to capture (default DEBUG — file handler sees all)

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    # Guard: don't add duplicate handlers if the logger is requested twice.
    if logger.handlers:
        return logger

    logger.setLevel(level)

    formatter = logging.Formatter(_FMT, datefmt=_DATEFMT)

    # ── Console handler (stdout, INFO and above) ──────────────────────────────
    # OS Concept: stdout is file descriptor 1, opened by the OS for every
    # process. Writing here goes to the terminal (or wherever the process's
    # stdout is redirected, e.g. a pipe).
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # ── Rotating file handler (DEBUG and above) ───────────────────────────────
    # RotatingFileHandler rolls over to a new file after maxBytes and keeps
    # backupCount old files — prevents the log from growing unboundedly and
    # filling the disk (a real OS concern for long-running servers).
    try:
        file_handler = RotatingFileHandler(
            _LOG_FILE,
            mode="a",          # O_APPEND — safe across restarts
            maxBytes=1_048_576,  # 1 MiB per file
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as exc:
        # If the log file cannot be opened (e.g., read-only filesystem),
        # continue with console-only logging rather than crashing.
        logger.warning("Could not open log file %s: %s — logging to console only", _LOG_FILE, exc)

    return logger


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log = get_logger("test")
    log.debug("debug message   (file only — not shown on console)")
    log.info("info message    (console + file)")
    log.warning("warning message (console + file)")
    log.error("error message   (console + file)")

    # Verify file was created
    if os.path.exists(_LOG_FILE):
        print(f"\nLog file created: {_LOG_FILE}")
        with open(_LOG_FILE, "r") as fh:
            lines = fh.readlines()
        print(f"Lines written to file: {len(lines)}")
        assert len(lines) >= 4, "Expected at least 4 log lines in file"
        print("logger.py self-test PASSED")
    else:
        print("FAIL — log file was not created")
        sys.exit(1)
