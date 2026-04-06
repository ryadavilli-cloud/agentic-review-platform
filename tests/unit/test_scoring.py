import uuid
from typing import Any

import pytest

from app.models.enums import FindingCategory, Severity
from app.models.finding import Evidence, Finding
from app.scoring.matcher import (
    score_findings,
)
from app.scoring.models import (
    ExpectedCodeFinding,
    ExpectedDependencyFinding,
    ExpectedFindings,
)
from app.tools.pip_audit_results import Dependency, DependencyScanResult, Vulnerability


def make_finding(
    *,
    file_path: str = "demo-packs/pack-a/app.py",
    line_start: int | None = 27,
    raw_output: str = "RULE-001",
    actual_finding_id: uuid.UUID | str | None = None,
    title: str = "Test finding",
    description: str = "Test description",
    severity: Severity = Severity.high,
    category: FindingCategory = FindingCategory.code_quality,
) -> Finding:
    if actual_finding_id is None:
        finding_uuid = uuid.uuid4()
    elif isinstance(actual_finding_id, uuid.UUID):
        finding_uuid = actual_finding_id
    else:
        finding_uuid = uuid.UUID(actual_finding_id)

    return Finding(
        id=finding_uuid,
        title=title,
        description=description,
        severity=severity,
        confidence=1.0,
        category=category,
        evidence=Evidence(
            tool_name="test-tool",
            raw_output=raw_output,
            file_path=file_path,
            line_start=line_start,
            line_end=line_start,
        ),
    )


def make_expected_code_finding(
    *,
    finding_id: str = "CODE-001",
    type: str = "sql-injection",
    file: str = "app.py",
    line: int = 27,
    severity: str = "high",
    detectable: bool = True,
    detectable_reason: str | None = None,
    description: str = "Expected code finding",
) -> ExpectedCodeFinding:
    return ExpectedCodeFinding(
        id=finding_id,
        tool="semgrep",
        type=type,
        file=file,
        line=line,
        severity=severity,
        detectable=detectable,
        detectable_reason=detectable_reason,
        description=description,
    )


def make_expected_dependency_finding(
    *,
    finding_id: str = "DEP-001",
    package: str = "werkzeug",
    version: str = "2.3.7",
    cve: str = "CVE-2023-46136",
    severity: str = "critical",
    detectable: bool = True,
    planned: bool = True,
) -> ExpectedDependencyFinding:
    return ExpectedDependencyFinding(
        id=finding_id,
        tool="pip-audit",
        package=package,
        version=version,
        cve=cve,
        severity=severity,
        detectable=detectable,
        planned=planned,
    )


def make_manifest(
    *,
    code_findings: list[ExpectedCodeFinding] | None = None,
    dependency_findings: list[ExpectedDependencyFinding] | None = None,
    version: str = "1.0",
) -> ExpectedFindings:
    return ExpectedFindings(
        version=version,
        code_findings=code_findings or [],
        dependency_findings=dependency_findings or [],
    )


def make_raw_scan(
    *,
    dependencies: list[dict[str, Any]],
) -> DependencyScanResult:
    """
    Example input:
    dependencies=[
        {
            "name": "werkzeug",
            "version": "2.3.7",
            "vulns": [
                {
                    "id": "PYSEC-2023-221",
                    "aliases": ["CVE-2023-46136", "GHSA-hrfv-mqp8-q5rw"],
                    "fix_versions": ["2.3.8"],
                    "description": "..."
                }
            ],
        }
    ]
    """
    dep_models: list[Dependency] = []

    for dep in dependencies or []:
        vuln_models = [
            Vulnerability(
                id=v["id"],
                aliases=v.get("aliases", []),
                fix_versions=v.get("fix_versions", []),
                description=v.get("description"),
            )
            for v in dep.get("vulns", [])
        ]

        dep_models.append(
            Dependency(
                name=dep["name"],
                version=dep["version"],
                vulns=vuln_models,
            )
        )

    return DependencyScanResult(dependencies=dep_models)


# test_code_perfect_detection — 3 expected, 3 matching actuals
@pytest.mark.unit
def test_code_perfect_detection():
    manifest = make_manifest(
        code_findings=[
            make_expected_code_finding(finding_id="CODE-001", line=10),
            make_expected_code_finding(finding_id="CODE-002", line=20),
            make_expected_code_finding(finding_id="CODE-003", line=30),
        ]
    )

    actual_findings = [
        make_finding(line_start=10),
        make_finding(line_start=20),
        make_finding(line_start=30),
    ]

    raw_scan = make_raw_scan(dependencies=[])

    code_score = score_findings(
        manifest,
        dep_findings=[],
        code_findings=actual_findings,
        raw_scan=raw_scan,
    )

    assert code_score.code.score.true_positives == 3
    assert code_score.code.score.false_positives == 0


# test_code_partial_detection — 3 expected, 2 match
@pytest.mark.unit
def test_code_partial_detection():
    manifest = make_manifest(
        code_findings=[
            make_expected_code_finding(finding_id="CODE-001", line=10),
            make_expected_code_finding(finding_id="CODE-002", line=20),
            make_expected_code_finding(finding_id="CODE-003", line=30),
        ]
    )

    actual_findings = [
        make_finding(line_start=10),
        make_finding(line_start=20),
        make_finding(line_start=40),  # does not match line 30
    ]

    raw_scan = make_raw_scan(dependencies=[])

    code_score = score_findings(
        manifest,
        dep_findings=[],
        code_findings=actual_findings,
        raw_scan=raw_scan,
    )

    assert code_score.code.score.true_positives == 2
    assert code_score.code.score.false_positives == 1


# test_code_false_positives — 2 expected + 1 extra actual
@pytest.mark.unit
def test_code_false_positives():
    manifest = make_manifest(
        code_findings=[
            make_expected_code_finding(finding_id="CODE-001", line=10),
            make_expected_code_finding(finding_id="CODE-002", line=20),
        ]
    )

    actual_findings = [
        make_finding(line_start=10),
        make_finding(line_start=20),
        make_finding(line_start=30),  # extra false positive
    ]

    raw_scan = make_raw_scan(dependencies=[])

    code_score = score_findings(
        manifest,
        dep_findings=[],
        code_findings=actual_findings,
        raw_scan=raw_scan,
    )

    assert code_score.code.score.true_positives == 2
    assert code_score.code.score.false_positives == 1


# test_code_dedup_same_line — 4 actuals on 2 lines, 2 expected
@pytest.mark.unit
def test_code_dedup_same_line():
    manifest = make_manifest(
        code_findings=[
            make_expected_code_finding(finding_id="CODE-001", line=10),
            make_expected_code_finding(finding_id="CODE-002", line=20),
        ]
    )

    actual_findings = [
        make_finding(line_start=10, raw_output="RULE-001"),
        make_finding(line_start=10, raw_output="RULE-002"),  # duplicate on same line
        make_finding(line_start=20, raw_output="RULE-003"),
        make_finding(line_start=20, raw_output="RULE-004"),  # duplicate on same line
    ]

    raw_scan = make_raw_scan(dependencies=[])

    code_score = score_findings(
        manifest,
        dep_findings=[],
        code_findings=actual_findings,
        raw_scan=raw_scan,
    )

    assert code_score.code.score.true_positives == 2
    assert code_score.code.score.false_positives == 0


# test_code_undetectable_excluded — 1 of 3 expected has detectable=false
@pytest.mark.unit
def test_code_undetectable_excluded():
    manifest = make_manifest(
        code_findings=[
            make_expected_code_finding(finding_id="CODE-001", line=10),
            make_expected_code_finding(
                finding_id="CODE-002",
                line=20,
                detectable=False,
                detectable_reason="Not detectable because of X",
            ),
            make_expected_code_finding(finding_id="CODE-003", line=30),
        ]
    )

    actual_findings = [
        make_finding(line_start=10),
        make_finding(line_start=30),
    ]

    raw_scan = make_raw_scan(dependencies=[])

    code_score = score_findings(
        manifest,
        dep_findings=[],
        code_findings=actual_findings,
        raw_scan=raw_scan,
    )

    assert code_score.code.score.true_positives == 2
    assert code_score.code.score.false_positives == 0


# test_code_line_tolerance — within and outside ±3
@pytest.mark.unit
def test_code_line_tolerance():
    manifest = make_manifest(
        code_findings=[
            make_expected_code_finding(finding_id="CODE-001", line=10),
            make_expected_code_finding(finding_id="CODE-002", line=20),
            make_expected_code_finding(finding_id="CODE-003", line=30),
        ]
    )

    actual_findings = [
        make_finding(line_start=8),  # within tolerance for CODE-001
        make_finding(line_start=23),  # within tolerance for CODE-002
        make_finding(line_start=35),  # outside tolerance for CODE-003
    ]

    raw_scan = make_raw_scan(dependencies=[])

    code_score = score_findings(
        manifest,
        dep_findings=[],
        code_findings=actual_findings,
        raw_scan=raw_scan,
    )

    assert code_score.code.score.true_positives == 2
    assert code_score.code.score.false_positives == 1


# test_code_zero_findings — 3 expected, 0 actual
@pytest.mark.unit
def test_code_zero_findings():
    manifest = make_manifest(
        code_findings=[
            make_expected_code_finding(finding_id="CODE-001", line=10),
            make_expected_code_finding(finding_id="CODE-002", line=20),
            make_expected_code_finding(finding_id="CODE-003", line=30),
        ]
    )

    actual_findings: list[Finding] = []

    raw_scan = make_raw_scan(dependencies=[])

    code_score = score_findings(
        manifest,
        dep_findings=[],
        code_findings=actual_findings,
        raw_scan=raw_scan,
    )

    assert code_score.code.score.true_positives == 0
    assert code_score.code.score.false_negatives == 3


# test_dep_alias_matching — manifest CVE, actual PYSEC, raw scan links them
@pytest.mark.unit
def test_dep_alias_matching():
    manifest = make_manifest(
        dependency_findings=[
            make_expected_dependency_finding(
                finding_id="DEP-001",
                package="werkzeug",
                version="2.3.7",
                cve="CVE-2023-46136",
                severity="critical",
                detectable=True,
                planned=True,
            )
        ]
    )

    actual_findings = [
        make_finding(
            raw_output="PYSEC-2023-221",
            category=FindingCategory.dependency,
        )
    ]

    raw_scan = make_raw_scan(
        dependencies=[
            {
                "name": "werkzeug",
                "version": "2.3.7",
                "vulns": [
                    {
                        "id": "PYSEC-2023-221",
                        "aliases": ["CVE-2023-46136", "GHSA-hrfv-mqp8-q5rw"],
                        "fix_versions": ["2.3.8"],
                        "description": "Test vulnerability description.",
                    }
                ],
            }
        ]
    )

    dep_score = score_findings(
        manifest,
        dep_findings=actual_findings,
        code_findings=[],
        raw_scan=raw_scan,
    )

    assert dep_score.dependency.score.true_positives == 1
    assert dep_score.dependency.score.false_positives == 0


# test_dep_dedup_cross_database — 2 duplicate actuals, 1 expected CVE
@pytest.mark.unit
def test_dep_dedup_cross_database():
    manifest = make_manifest(
        dependency_findings=[
            make_expected_dependency_finding(
                finding_id="DEP-001",
                package="werkzeug",
                version="2.3.7",
                cve="CVE-2023-46136",
                severity="critical",
                detectable=True,
                planned=True,
            )
        ]
    )

    actual_findings = [
        make_finding(
            raw_output="PYSEC-2023-221",
            category=FindingCategory.dependency,
        ),
        make_finding(
            raw_output="CVE-2023-46136",
            category=FindingCategory.dependency,
        ),
    ]

    raw_scan = make_raw_scan(
        dependencies=[
            {
                "name": "werkzeug",
                "version": "2.3.7",
                "vulns": [
                    {
                        "id": "PYSEC-2023-221",
                        "aliases": ["CVE-2023-46136", "GHSA-hrfv-mqp8-q5rw"],
                        "fix_versions": ["2.3.8"],
                        "description": "Test vulnerability description.",
                    }
                ],
            }
        ]
    )

    dep_score = score_findings(
        manifest,
        dep_findings=actual_findings,
        code_findings=[],
        raw_scan=raw_scan,
    )

    assert dep_score.dependency.score.true_positives == 1
    assert dep_score.dependency.score.false_positives == 0


# test_dep_unmatched_cve — expected CVE not in actuals
@pytest.mark.unit
def test_dep_unmatched_cve():
    manifest = make_manifest(
        dependency_findings=[
            make_expected_dependency_finding(
                finding_id="DEP-001",
                package="werkzeug",
                version="2.3.7",
                cve="CVE-2023-46136",
                severity="critical",
                detectable=True,
                planned=True,
            )
        ]
    )

    actual_findings: list[Finding] = []

    raw_scan = make_raw_scan(
        dependencies=[
            {
                "name": "werkzeug",
                "version": "2.3.7",
                "vulns": [
                    {
                        "id": "PYSEC-2023-221",
                        "aliases": ["CVE-2023-46136", "GHSA-hrfv-mqp8-q5rw"],
                        "fix_versions": ["2.3.8"],
                        "description": "Test vulnerability description.",
                    }
                ],
            }
        ]
    )

    dep_score = score_findings(
        manifest,
        dep_findings=actual_findings,
        code_findings=[],
        raw_scan=raw_scan,
    )

    assert dep_score.dependency.score.true_positives == 0
    assert dep_score.dependency.score.false_negatives == 1


# test_dep_unplanned_finding — actual CVE not in manifest
@pytest.mark.unit
def test_dep_unplanned_finding():
    manifest = make_manifest(dependency_findings=[])

    actual_findings = [
        make_finding(
            raw_output="PYSEC-2023-221",
            category=FindingCategory.dependency,
        )
    ]

    raw_scan = make_raw_scan(
        dependencies=[
            {
                "name": "werkzeug",
                "version": "2.3.7",
                "vulns": [
                    {
                        "id": "PYSEC-2023-221",
                        "aliases": ["CVE-2023-46136", "GHSA-hrfv-mqp8-q5rw"],
                        "fix_versions": ["2.3.8"],
                        "description": "Test vulnerability description.",
                    }
                ],
            }
        ]
    )

    dep_score = score_findings(
        manifest,
        dep_findings=actual_findings,
        code_findings=[],
        raw_scan=raw_scan,
    )
    assert dep_score.dependency.score.true_positives == 0
    assert dep_score.dependency.score.false_positives == 1


# test_combined_score_merge — code + dep scores merge correctly
@pytest.mark.unit
def test_combined_score_merge():
    code_actuals = [
        make_finding(line_start=10),
    ]

    dep_actuals = [
        make_finding(
            raw_output="PYSEC-2023-221",
            category=FindingCategory.dependency,
        ),
    ]

    manifest = make_manifest(
        code_findings=[
            make_expected_code_finding(finding_id="CODE-001", line=10),
        ],
        dependency_findings=[
            make_expected_dependency_finding(
                finding_id="DEP-001",
                package="werkzeug",
                version="2.3.7",
                cve="CVE-2023-46136",
                severity="critical",
                detectable=True,
                planned=True,
            )
        ],
    )

    raw_scan = make_raw_scan(
        dependencies=[
            {
                "name": "werkzeug",
                "version": "2.3.7",
                "vulns": [
                    {
                        "id": "PYSEC-2023-221",
                        "aliases": ["CVE-2023-46136", "GHSA-hrfv-mqp8-q5rw"],
                        "fix_versions": ["2.3.8"],
                        "description": "Test vulnerability description.",
                    }
                ],
            }
        ]
    )

    combined_score = score_findings(
        manifest,
        code_findings=code_actuals,
        dep_findings=dep_actuals,
        raw_scan=raw_scan,
    )

    assert combined_score.code.score.true_positives == 1
    assert combined_score.code.score.false_positives == 0
    assert combined_score.dependency.score.true_positives == 1
    assert combined_score.dependency.score.false_positives == 0
    assert combined_score.combined.true_positives == 2
    assert combined_score.combined.false_positives == 0
