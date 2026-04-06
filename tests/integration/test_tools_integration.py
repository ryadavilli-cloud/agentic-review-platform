import pytest

from app.tools.pip_audit import PipAuditTool
from app.tools.semgrep import SemgrepTool


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pip_audit_integration():
    results = await PipAuditTool().run("demo-packs/pack-a/requirements.txt")
    assert results.tool_name == "pip-audit"
    assert results.packages_scanned >= 10


@pytest.mark.integration
@pytest.mark.asyncio
async def test_semgrep_integration():
    results = await SemgrepTool().run("demo-packs/pack-a/")
    assert results.tool_name == "semgrep"
    assert results.files_scanned >= 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_semgrep_findings():
    results = await SemgrepTool().run("demo-packs/pack-a/")
    assert results.tool_name == "semgrep"
    assert results.success is True
    unique_lines = {f.evidence.line_start for f in results.parsed_findings}
    assert len(unique_lines) >= 11
    assert len(results.parsed_findings) == 27


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pip_audit_findings():
    results = await PipAuditTool().run("demo-packs/pack-a/requirements.txt")
    assert results.tool_name == "pip-audit"
    assert results.success is True
    expected_findings = [
        "flask",
        "jinja2",
        "werkzeug",
        "pyyaml",
        "urllib3",
        "requests",
        "cryptography",
    ]

    for package in expected_findings:
        assert any(package in f.title.lower() for f in results.parsed_findings), (
            f"Expected package not found: {package}"
        )
