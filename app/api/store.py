from pathlib import Path
from uuid import UUID

from app.models import SecurityReport

# Module-level in-memory report store
_REPORT_STORE: dict[UUID, SecurityReport] = {}

# Module-level scenario registry
_SCENARIOS: dict[str, dict[str, str]] = {
    "pack-a": {
        "id": "pack-a",
        "name": "Vulnerable Python Service",
        "description": "Flask app with seeded security issues "
        "and vulnerable dependencies",
        "path": "demo-packs/pack-a",
    }
}


def save_report(report: SecurityReport) -> None:
    _REPORT_STORE[report.id] = report


def get_report(report_id: UUID) -> SecurityReport | None:
    return _REPORT_STORE.get(report_id)


def list_demo_scenarios() -> list[dict[str, str]]:
    return list(_SCENARIOS.values())


def resolve_scenario_path(scenario_id: str) -> str | None:
    scenario = _SCENARIOS.get(scenario_id)
    if scenario is None:
        return None

    return str(Path(scenario["path"]))
