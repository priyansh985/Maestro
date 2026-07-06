"""Reproduce the paper end-to-end: TC1 + TC2 + Table 4 + Table 5.

Implements the Sec 3.1 control loop with deterministic stub LLM (assumption
A1) so the reproduction runs offline. Outputs land in ``results/``.

Run with: ``python -m maestro.experiments.runner``
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

import pandas as pd

from ..config import load_config
from ..logging_setup import get_logger
from .summary import table_4_dataframe, table_5_dataframe, write_repo_tables
from .tc1_dos import TC1Result, run_tc1
from .tc2_memory_poison import run_tc2


async def reproduce(cfg=None, out_dir: str | Path = "results") -> dict:
    """End-to-end Sec 6.3 reproduction."""
    if cfg is None:
        cfg = load_config()
    log_file = str(cfg.logging.file) if hasattr(cfg.logging, "file") else None
    logger = get_logger("maestro.repro",
                        level=str(cfg.logging.level),
                        log_file=log_file)
    logger.info("=== Sec 4-6 reproduction: load config ===")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    logger.info("=== Sec 4.3.2 Table 4 - threat matrix ===")
    table4 = table_4_dataframe(cfg)
    logger.info("Computed %d threats", len(table4))

    logger.info("=== Sec 6.3 TC1 - DoS replay (Sec 6.2 protocol) ===")
    tc1: TC1Result = await run_tc1(cfg)

    logger.info("=== Sec 6.3 TC2 - Memory poisoning ===")
    tc2 = run_tc2(cfg)

    logger.info("=== Sec 6.3 Table 5 - security risk validation ===")
    table5 = table_5_dataframe(tc1, tc2)

    paths = write_repo_tables(out, table4, table5)
    (out / "tc1.json").write_text(json.dumps(tc1.as_dict(), indent=2), encoding="utf-8")
    (out / "tc2.json").write_text(json.dumps(tc2.as_dict(), indent=2), encoding="utf-8")
    logger.info("Wrote tables/results to %s", out)
    logger.info("TC1 attack telemetry interval = %.2fs (baseline %.2fs)",
                tc1.attack_tel_s, tc1.baseline_tel_s)
    logger.info("TC2 post-poison capture duration = %.2fs (baseline %.2fs)",
                tc2.post_capture_duration_s, tc2.baseline_capture_duration_s)
    return {
        "table4": table4.to_dict(orient="records"),
        "table5": table5.to_dict(orient="records"),
        "tc1": tc1.as_dict(),
        "tc2": tc2.as_dict(),
        "out_dir": str(out),
        "paths": {k: str(v) for k, v in paths.items()},
    }


def main() -> None:
    cfg = load_config()
    asyncio.run(reproduce(cfg=cfg))


if __name__ == "__main__":
    main()
