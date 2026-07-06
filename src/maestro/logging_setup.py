"""Centralized structured logging (Sec 3 of reproduce.sh spec).

All major stages log via :func:`get_logger` so failures are traceable.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional


_CONFIGURED: dict[str, logging.Logger] = {}


def get_logger(name: str = "maestro", level: str = "INFO",
               log_file: Optional[str | Path] = None) -> logging.Logger:
    if name in _CONFIGURED:
        return _CONFIGURED[name]
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    _CONFIGURED[name] = logger
    return logger
