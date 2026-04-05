import pytest
from pydantic import ValidationError

from app.models.enums import Severity
from app.tools.pip_audit import PipAuditTool

# Test 1 — Happy path with multiple vulnerabilities. Feed in JSON with 2-3 dependencies,
# some with vulns, some clean. Verify: correct number of Finding objects,
# packages_scanned count, vulnerabilities_found count, success is True.


@pytest.mark.unit
def test_transform_pip_audit_output_multiple_vulns():
    pip_audit_tool = PipAuditTool()
    raw_output = """
    {
  "dependencies": [
    {
      "name": "python-dotenv",
      "version": "1.0.0",
      "vulns": []
    },
    {
      "name": "gunicorn",
      "version": "21.2.0",
      "vulns": [
        {
          "id": "CVE-2024-1135",
          "fix_versions": ["22.0.0"],
          "aliases": ["GHSA-w3h3-4rj7-4ph4"],
          "description": "Gunicorn fails to properly validate Transfer-Encoding \
            headers, leading to HTTP Request Smuggling vulnerabilities."
        },
        {
          "id": "CVE-2024-6827",
          "fix_versions": ["22.0.0"],
          "aliases": ["GHSA-hc5x-x2vx-497g"],
          "description": "Gunicorn does not properly validate the Transfer-Encoding \
            header, leading to request smuggling risk."
        }
      ]
    },
    {
      "name": "sqlparse",
      "version": "0.5.0",
      "vulns": [
        {
          "id": "GHSA-27jp-wm6q-gp25",
          "fix_versions": ["0.5.4"],
          "aliases": [],
          "description": "Formatting a long list of tuples may hang and cause a\
              denial of service."
        }
      ]
    }
  ],
  "fixes": []
}
    """

    pip_audit_result = pip_audit_tool.transform_pip_audit_output(raw_output)
    assert pip_audit_result.success is True
    assert pip_audit_result.packages_scanned == 3
    assert pip_audit_result.vulnerabilities_found == 3
    assert len(pip_audit_result.parsed_findings) == 3


# Test 2 — Empty dependencies list. Feed in {"dependencies": []}. Verify: zero findings,
# packages_scanned=0, vulnerabilities_found=0, success=True.


@pytest.mark.unit
def test_transform_pip_audit_output_empty_dependencies():
    pip_audit_tool = PipAuditTool()
    raw_output = """
    {
      "dependencies": [],
      "fixes": []
    }
    """

    pip_audit_result = pip_audit_tool.transform_pip_audit_output(raw_output)
    assert pip_audit_result.success is True
    assert pip_audit_result.packages_scanned == 0
    assert pip_audit_result.vulnerabilities_found == 0
    assert len(pip_audit_result.parsed_findings) == 0


# Test 3 — All clean packages. Feed in JSON with 3 dependencies, all with empty vulns
# lists. Verify: zero findings, packages_scanned=3, vulnerabilities_found=0.
@pytest.mark.unit
def test_transform_pip_audit_output_all_clean():
    pip_audit_tool = PipAuditTool()
    raw_output = """
    {
  "dependencies": [
    {
      "name": "python-dotenv",
      "version": "1.0.0",
      "vulns": []
    },
    {
      "name": "click",
      "version": "8.3.2",
      "vulns": []
    },
    {
      "name": "certifi",
      "version": "2026.2.25",
      "vulns": []
    }
  ],
  "fixes": []
}
    """

    pip_audit_result = pip_audit_tool.transform_pip_audit_output(raw_output)
    assert pip_audit_result.success is True
    assert pip_audit_result.packages_scanned == 3
    assert pip_audit_result.vulnerabilities_found == 0
    assert len(pip_audit_result.parsed_findings) == 0


# Test 4 — Severity mapping. Verify that vulns with CVE in the ID get Severity.critical,
#  and vulns with PYSEC or GHSA IDs get Severity.high. Feed in one of each
# and check the resulting findings.
@pytest.mark.unit
def test_transform_pip_audit_output_severity_mapping():
    pip_audit_tool = PipAuditTool()
    raw_output = """
    {
  "dependencies": [
    {
      "name": "flask",
      "version": "2.3.2",
      "vulns": [
        {
          "id": "CVE-2026-27205",
          "fix_versions": ["3.1.3"],
          "aliases": ["GHSA-68rp-wp8r-4726"],
          "description": "Flask may fail to set the Vary: Cookie header \
            in some session access patterns."
        }
      ]
    },
    {
      "name": "pyyaml",
      "version": "5.3.1",
      "vulns": [
        {
          "id": "PYSEC-2021-142",
          "fix_versions": ["5.4"],
          "aliases": ["GHSA-8q59-q68h-6hv4", "CVE-2020-14343"],
          "description": "PyYAML may allow arbitrary code execution when \
            processing untrusted YAML with FullLoader."
        }
      ]
    },
    {
      "name": "sqlparse",
      "version": "0.5.0",
      "vulns": [
        {
          "id": "GHSA-27jp-wm6q-gp25",
          "fix_versions": ["0.5.4"],
          "aliases": [],
          "description": "Formatting a long list of tuples may hang and \
          cause a denial of service."
        }
      ]
    }
  ],
  "fixes": []
}
"""
    pip_audit_result = pip_audit_tool.transform_pip_audit_output(raw_output)
    assert pip_audit_result.success is True
    assert pip_audit_result.packages_scanned == 3
    assert pip_audit_result.vulnerabilities_found == 3
    assert len(pip_audit_result.parsed_findings) == 3

    assert pip_audit_result.parsed_findings[0].severity == Severity.critical  # CVE
    assert pip_audit_result.parsed_findings[1].severity == Severity.high  # PYSEC
    assert pip_audit_result.parsed_findings[2].severity == Severity.high  # GHSA


# Test 5 — Missing optional fields. Feed in a vulnerability with description=None,
# empty fix_versions, empty aliases. Verify the transform handles it gracefully —
# Finding.description should be "No description provided".
@pytest.mark.unit
def test_transform_pip_audit_output_missing_optional_fields():
    pip_audit_tool = PipAuditTool()
    raw_output = """
    {
  "dependencies": [
    {
      "name": "demo-package",
      "version": "1.2.3",
      "vulns": [
        {
          "id": "GHSA-demo-1234-5678",
          "fix_versions": [],
          "aliases": [],
          "description": null
        }
      ]
    }
  ],
  "fixes": []
}
"""
    pip_audit_result = pip_audit_tool.transform_pip_audit_output(raw_output)
    assert pip_audit_result.success is True
    assert pip_audit_result.packages_scanned == 1
    assert pip_audit_result.vulnerabilities_found == 1
    assert len(pip_audit_result.parsed_findings) == 1
    finding = pip_audit_result.parsed_findings[0]
    assert finding.severity == Severity.high  # GHSA should map to high
    assert finding.description == "No description provided"


# Test 6 — Duplicate vulnerability IDs. Feed in the same PYSEC-2023-221 twice for
# werkzeug (matching your real output). Verify both produce separate Finding objects
#  — no dedup at this layer.
@pytest.mark.unit
def test_transform_pip_audit_output_duplicate_vuln_ids():
    pip_audit_tool = PipAuditTool()
    raw_output = """
 {
  "dependencies": [
    {
      "name": "werkzeug",
      "version": "2.3.7",
      "vulns": [
        {
          "id": "PYSEC-2023-221",
          "fix_versions": ["2.3.8", "3.0.1"],
          "aliases": ["GHSA-hrfv-mqp8-q5rw", "CVE-2023-46136"],
          "description": "Werkzeug multipart data parser may consume excessive CPU \
            and memory when parsing crafted multipart uploads."
        },
        {
            "id": "PYSEC-2023-221",
            "fix_versions": ["2.3.8", "3.0.1"],
            "aliases": ["GHSA-hrfv-mqp8-q5rw", "CVE-2023-46136"],
            "description": "Werkzeug multipart parsing can be abused for denial \
            of service through crafted  multipart form data."
        }
      ]
    }
  ],
  "fixes": []
}
"""
    pip_audit_result = pip_audit_tool.transform_pip_audit_output(raw_output)
    assert pip_audit_result.success is True
    assert pip_audit_result.packages_scanned == 1
    assert pip_audit_result.vulnerabilities_found == 2
    assert len(pip_audit_result.parsed_findings) == 2


# Test 7 — Error string from server. Feed in "Error: File 'bad.txt' not found." —
# this isn't valid JSON. Verify the transform raises a ValidationError
# (or whatever you want the behavior to be). This tests what happens when the
#  MCP server returns an error message instead of JSON.
@pytest.mark.unit
def test_transform_pip_audit_output_error_string_raises_validation_error():
    tool = PipAuditTool()

    raw_output = "Error: File 'bad.txt' not found."

    with pytest.raises(ValidationError):
        tool.transform_pip_audit_output(raw_output)


# Test 8 — Evidence fields correct. Verify that each Finding.evidence has
# tool_name="pip-audit", file_path="requirements.txt",
# and raw_output contains the vulnerability ID.
@pytest.mark.unit
def test_transform_pip_audit_output_evidence_fields():
    pip_audit_tool = PipAuditTool()
    raw_output = """
    {
  "dependencies": [
    {
      "name": "gunicorn",
      "version": "21.2.0",
      "vulns": [
        {
          "id": "CVE-2024-1135",
          "fix_versions": ["22.0.0"],
          "aliases": ["GHSA-w3h3-4rj7-4ph4"],
          "description": "Gunicorn fails to properly validate \
            Transfer-Encoding headers."
        }
      ]
    },
    {
      "name": "sqlparse",
      "version": "0.5.0",
      "vulns": [
        {
          "id": "GHSA-27jp-wm6q-gp25",
          "fix_versions": ["0.5.4"],
          "aliases": [],
          "description": "Formatting a long list of tuples may hang and cause a denial \
            of service."
        }
      ]
    }
  ],
  "fixes": []
}
"""
    result = pip_audit_tool.transform_pip_audit_output(raw_output)

    assert result.vulnerabilities_found == 2
    assert len(result.parsed_findings) == 2
    assert result.parsed_findings[0].evidence.tool_name == "pip-audit"
    assert result.parsed_findings[0].evidence.file_path == "requirements.txt"
    assert result.parsed_findings[0].evidence.raw_output == "CVE-2024-1135"

    assert result.parsed_findings[1].evidence.tool_name == "pip-audit"
    assert result.parsed_findings[1].evidence.file_path == "requirements.txt"
    assert result.parsed_findings[1].evidence.raw_output == "GHSA-27jp-wm6q-gp25"
