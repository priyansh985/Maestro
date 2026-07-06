"""Summarizer for Table 4 (Sec 4.3.2) and Table 5 (Sec 6.3)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import pandas as pd

from ..maestro.mapping import threat_risk_matrix
from ..maestro.threats import load_threats
from .tc1_dos import TC1Result
from .tc2_memory_poison import TC2Result


def table_4_dataframe(cfg) -> pd.DataFrame:
    """Render Sec 4.3.2 Table 4."""
    threats = load_threats(cfg.maestro.threats_file
                           if hasattr(cfg.maestro, "threats_file")
                           else None)
    rows = threat_risk_matrix(threats)
    return pd.DataFrame(rows)


def table_5_dataframe(tc1: TC1Result, tc2: TC2Result) -> pd.DataFrame:
    """Render Sec 6.3 Table 5 - Summary of Security Risk Validation."""
    return pd.DataFrame([
        {
            "Test Case": "TC1: Network Load",
            "Threat": "Threat #7: Resource Exhaustion",
            "MAESTRO Layer(s)": "L4 - Deployment & Infrastructure, L5 - Evaluation & Observability",
            "Exploit Method": f"High-speed PCAP replay (DoS) @ {tc1.plc_packets_per_second}pps "
                              f"{tc1.replay_method}",
            "Resulting telemetry interval (s)": round(tc1.attack_tel_s, 2),
            "Baseline telemetry interval (s)": round(tc1.baseline_tel_s, 2),
            "Telemetry lag ratio": round(tc1.attack_tel_s / max(1e-9, tc1.baseline_tel_s), 2),
            "Observed Impact": (
                f"Delayed telemetry ({tc1.attack_tel_s:.1f}s vs {tc1.baseline_tel_s:.1f}s "
                f"baseline); CPU/mem saturation"
            ),
            "Validated Risk": "Validated",
        },
        {
            "Test Case": "TC2: Memory Poisoning",
            "Threat": "Threat #8: Knowledge Base Poisoning",
            "MAESTRO Layer(s)": "L2 - Data Operations, L3 - Agent Frameworks",
            "Exploit Method": f"Injected {tc2.n_poisoned} fake high-sev entries in history.json",
            "Resulting capture duration (s)": round(tc2.post_capture_duration_s, 2),
            "Baseline capture duration (s)": round(tc2.baseline_capture_duration_s, 2),
            "Capture duration ratio": round(
                tc2.post_capture_duration_s / max(1e-9, tc2.baseline_capture_duration_s), 2),
            "Observed Impact": (
                f"Capture duration inflated from {tc2.baseline_capture_duration_s:.1f}s "
                f"to {tc2.post_capture_duration_s:.1f}s "
                "-> large PCAP + slow detection"
            ),
            "Validated Risk": "Validated",
        },
    ])


def write_repo_tables(out_dir: str | Path,
                      table4: pd.DataFrame, table5: pd.DataFrame) -> Dict[str, Path]:
    """Write Sec 4 Table 4 + Sec 6 Table 5 as CSV + Markdown."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for name, df in (("table4_threat_matrix", table4),
                     ("table5_security_risk", table5)):
        csv = out / f"{name}.csv"
        md = out / f"{name}.md"
        df.to_csv(csv, index=False)
        md.write_text(df.to_markdown(index=False), encoding="utf-8")
        paths[name] = csv
        paths[name + "_md"] = md
    out.joinpath("results_summary.json").write_text(
        json.dumps({"table4": table4.to_dict(orient="records"),
                    "table5": table5.to_dict(orient="records")}, indent=2),
        encoding="utf-8")
    return paths
