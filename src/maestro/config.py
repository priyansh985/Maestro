"""``src/maestro/config.py`` — single entry point for loading ``configs/default.yaml``.

All modules in the reproduction read hyperparameters from this loader; no magic
numbers are allowed in logic. Implements the "no magic numbers in logic" rule
from Stage 3.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

from omegaconf import DictConfig, OmegaConf

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_CONFIG = _REPO_ROOT / "configs" / "default.yaml"


def load_config(path: str | os.PathLike[str] | None = None) -> DictConfig:
    """Load the YAML config and interpolate references.

    Parameters
    ----------
    path:
        Optional override. Defaults to ``configs/default.yaml``.
    """
    cfg_path = Path(path) if path is not None else _DEFAULT_CONFIG
    return cast(DictConfig, OmegaConf.load(cfg_path))


def cfg_get(cfg: DictConfig, key: str, default: Any = None) -> Any:
    """Dot-path getter, e.g. ``cfg_get(cfg, "dos_replay.iterations")``."""
    cur: Any = cfg
    for part in key.split("."):
        if cur is None:
            return default
        cur = getattr(cur, part, None) if isinstance(cur, DictConfig) else None
    return default if cur is None else cur
