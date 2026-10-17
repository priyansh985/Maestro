"""MAESTRO operator dashboard HTML (Sec 3.1 Interactive Dashboard).

The template lives on disk next to this module (``dashboard.html``) so it can
be edited without touching Python; this module loads it once at import time.
The SPA talks to the live control plane over REST (``/api/...``, see
``control_api``) and the WebSocket at ``/ws``.
"""
from __future__ import annotations

from pathlib import Path

DASHBOARD_HTML = (
    Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
)

__all__ = ["DASHBOARD_HTML"]