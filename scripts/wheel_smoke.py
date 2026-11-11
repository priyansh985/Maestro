"""Run with the built wheel installed into a fresh environment outside the checkout."""
from importlib.metadata import distribution, version
from pathlib import Path

import maestro
from maestro.config import load_config
from maestro.connectors.config import build_registry
from maestro.maestro.threats import load_threats
from maestro.scripts.validate_threats import main as validate_threats
from maestro.server.app import create_app
from maestro.server.dashboards.dashboard import DASHBOARD_HTML

repo = Path(__file__).resolve().parents[1]
installed = Path(maestro.__file__).resolve()
if installed.is_relative_to(repo / "src"):
    raise SystemExit("wheel smoke imported the source checkout instead of the wheel")
assert maestro.__version__ == version("maestro-secure-agentic-ai")
for entry in distribution("maestro-secure-agentic-ai").entry_points.select(group="console_scripts"):
    assert callable(entry.load()), entry.name
assert load_config().server.port
assert len(load_threats()) == 10
assert "stub" in build_registry().names()
assert "<html" in DASHBOARD_HTML.lower()
assert create_app().title
assert validate_threats() == 0
print(f"Installed wheel smoke passed: {installed}")
