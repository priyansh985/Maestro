"""Tests for the Table 4 / Table 5 summarizer (Sec 4.3.2 + Sec 6.3)."""
from __future__ import annotations

import json

from maestro.config import load_config
from maestro.experiments.summary import table_4_dataframe, table_5_dataframe, write_repo_tables
from maestro.experiments.tc1_dos import TC1Result
from maestro.experiments.tc2_memory_poison import TC2Result


def test_table4_dataframe_matches_paper():
    cfg = load_config()
    df = table_4_dataframe(cfg)
    assert len(df) == 10
    row7 = df[df["Threat"].str.startswith("7.")].iloc[0]
    assert int(row7["Risk Score"]) == 27
    row8 = df[df["Threat"].str.startswith("8.")].iloc[0]
    assert int(row8["Risk Score"]) == 9


def _tc1() -> TC1Result:
    return TC1Result(iterations=5, baseline_tel_s=7.0, attack_tel_s=13.0,
                     plc_packets_per_second=10000, replay_method="scapy")


def _tc2() -> TC2Result:
    return TC2Result(history_path="h.json", n_poisoned=20,
                     n_baseline_high_severity=0, n_post_high_severity=20,
                     baseline_capture_duration_s=34.0,
                     post_capture_duration_s=94.0)


def test_table5_dataframe_columns():
    df = table_5_dataframe(_tc1(), _tc2())
    assert len(df) == 2
    assert set(df["Test Case"]) == {"TC1: Network Load", "TC2: Memory Poisoning"}
    assert "Threat #7: Resource Exhaustion" in set(df["Threat"])
    assert "Threat #8: Knowledge Base Poisoning" in set(df["Threat"])


def test_write_repo_tables_emits_all_artifacts(tmp_path):
    cfg = load_config()
    t4 = table_4_dataframe(cfg)
    t5 = table_5_dataframe(_tc1(), _tc2())
    paths = write_repo_tables(tmp_path, t4, t5)
    for name in ("table4_threat_matrix", "table5_security_risk"):
        assert (tmp_path / f"{name}.csv").exists()
        assert (tmp_path / f"{name}.md").exists()
    summary = json.loads((tmp_path / "results_summary.json").read_text(encoding="utf-8"))
    assert len(summary["table4"]) == 10
    assert len(summary["table5"]) == 2
    assert paths  # returned path map is non-empty
