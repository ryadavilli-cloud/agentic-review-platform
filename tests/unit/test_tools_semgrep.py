from pathlib import Path

import pytest

from app.models.enums import Severity
from app.tools.semgrep import SemgrepTool


@pytest.mark.unit
def test_semgrep_transform_output_valid():
    semgrep_tool = SemgrepTool()
    raw_output = """
{
  "results": [
    {
      "check_id": "rule-1",
      "path": "app/file1.py",
      "start": {
        "line": 10,
        "col": 1,
        "offset": 100
      },
      "end": {
        "line": 10,
        "col": 5,
        "offset": 104
      },
      "extra": {
        "message": "Test finding 1",
        "severity": "ERROR",
        "metadata": {
          "category": "security",
          "confidence": "HIGH"
        }
      }
    },
    {
      "check_id": "rule-2",
      "path": "app/file2.py",
      "start": {
        "line": 20,
        "col": 2,
        "offset": 200
      },
      "end": {
        "line": 20,
        "col": 6,
        "offset": 204
      },
      "extra": {
        "message": "Test finding 2",
        "severity": "WARNING",
        "metadata": {
          "category": "correctness",
          "confidence": "MEDIUM"
        }
      }
    },
    {
      "check_id": "rule-3",
      "path": "app/file3.py",
      "start": {
        "line": 30,
        "col": 3,
        "offset": 300
      },
      "end": {
        "line": 30,
        "col": 7,
        "offset": 304
      },
      "extra": {
        "message": "Test finding 3",
        "severity": "INFO",
        "metadata": {
          "category": "best-practice",
          "confidence": "LOW"
        }
      }
    }
  ],
  "errors": [],
  "paths": {
    "scanned": ["app/file1.py", "app/file2.py", "app/file3.py"]
  },
  "version": "1.0.0"
}
"""

    execution_time = 0.0

    result = semgrep_tool.transform_semgrep_output(raw_output, execution_time)

    assert result.tool_name == "semgrep"
    assert result.success is True
    assert len(result.parsed_findings) > 0
    assert result.execution_time_seconds == execution_time
    assert result.rules_matched == 3
    assert result.files_scanned == 3

    assert result.parsed_findings[0].evidence.file_path == "app/file1.py"
    assert result.parsed_findings[0].evidence.line_start == 10
    assert result.parsed_findings[0].evidence.line_end == 10
    assert result.parsed_findings[0].title == "Test finding 1"


@pytest.mark.unit
def test_semgrep_transform_output_empty():
    semgrep_tool = SemgrepTool()
    raw_output = """
{
  "results": [],
  "errors": [],
  "paths": {
    "scanned": [
      "app/file1.py"
    ]
  },
  "version": "1.0.0"
}
"""

    execution_time = 0.0

    result = semgrep_tool.transform_semgrep_output(raw_output, execution_time)

    assert result.tool_name == "semgrep"
    # assert result.raw_output == raw_output
    assert result.success is True
    assert result.files_scanned == 1
    assert len(result.parsed_findings) == 0


@pytest.mark.unit
def test_semgrep_transform_output_severity():
    semgrep_tool = SemgrepTool()
    raw_output = """
{
  "results": [
    {
      "check_id": "rule-error",
      "path": "app/file1.py",
      "start": {
        "line": 10,
        "col": 1,
        "offset": 100
      },
      "end": {
        "line": 10,
        "col": 5,
        "offset": 104
      },
      "extra": {
        "message": "Test finding with ERROR severity",
        "severity": "ERROR",
        "metadata": {
          "category": "security",
          "confidence": "HIGH"
        }
      }
    },
    {
      "check_id": "rule-warning",
      "path": "app/file2.py",
      "start": {
        "line": 20,
        "col": 2,
        "offset": 200
      },
      "end": {
        "line": 20,
        "col": 6,
        "offset": 204
      },
      "extra": {
        "message": "Test finding with WARNING severity",
        "severity": "WARNING",
        "metadata": {
          "category": "correctness",
          "confidence": "MEDIUM"
        }
      }
    },
    {
      "check_id": "rule-info",
      "path": "app/file3.py",
      "start": {
        "line": 30,
        "col": 3,
        "offset": 300
      },
      "end": {
        "line": 30,
        "col": 7,
        "offset": 304
      },
      "extra": {
        "message": "Test finding with INFO severity",
        "severity": "INFO",
        "metadata": {
          "category": "best-practice",
          "confidence": "LOW"
        }
      }
    }
  ],
  "errors": [],
  "paths": {
    "scanned": [
      "app/file1.py",
      "app/file2.py",
      "app/file3.py"
    ]
  },
  "version": "1.0.0"
}
"""

    execution_time = 0.0

    result = semgrep_tool.transform_semgrep_output(raw_output, execution_time)

    assert result.tool_name == "semgrep"
    assert result.success is True
    assert len(result.parsed_findings) == 3
    assert result.parsed_findings[0].severity == Severity.high
    assert result.parsed_findings[1].severity == Severity.medium
    assert result.parsed_findings[2].severity == Severity.low


@pytest.mark.unit
def test_semgrep_transform_output_invalid_severity():
    semgrep_tool = SemgrepTool()
    raw_output = """
{
  "results": [
    {
      "check_id": "rule-critical",
      "path": "app/file1.py",
      "start": {
        "line": 10,
        "col": 1,
        "offset": 100
      },
      "end": {
        "line": 10,
        "col": 5,
        "offset": 104
      },
      "extra": {
        "message": "Test finding with CRITICAL severity",
        "severity": "CRITICAL",
        "metadata": {
          "category": "security",
          "confidence": "HIGH"
        }
      }
    }
  ],
  "errors": [],
  "paths": {
    "scanned": [
      "app/file1.py"
    ]
  },
  "version": "1.0.0"
}
"""
    execution_time = 0.0

    result = semgrep_tool.transform_semgrep_output(raw_output, execution_time)

    assert (
        result.parsed_findings[0].severity == Severity.low
    )  # Default to low severity for unrecognized severity levels


@pytest.mark.unit
def test_semgrep_transform_output_errors():
    semgrep_tool = SemgrepTool()
    raw_output = """
{
  "results": [],
  "errors": [
    "Failed to parse one or more files.",
    "Timeout while scanning app/file2.py"
  ],
  "paths": {
    "scanned": [
      "app/file1.py"
    ]
  },
  "version": "1.0.0"
}
"""
    execution_time = 0.0

    result = semgrep_tool.transform_semgrep_output(raw_output, execution_time)

    assert result.success is False


@pytest.mark.unit
def test_semgrep_transform_output_opetional_missing():
    semgrep_tool = SemgrepTool()
    raw_output = """
{
  "results": [
    {
      "check_id": "rule-minimal-metadata",
      "path": "app/file1.py",
      "start": {
        "line": 15,
        "col": 4,
        "offset": 150
      },
      "end": {
        "line": 15,
        "col": 12,
        "offset": 158
      },
      "extra": {
        "message": "Test finding with minimal metadata",
        "severity": "WARNING",
        "metadata": {
          "category": "security",
          "confidence": "MEDIUM"
        }
      }
    }
  ],
  "errors": [],
  "paths": {
    "scanned": [
      "app/file1.py"
    ]
  },
  "version": "1.0.0"
}
"""
    execution_time = 0.0

    result = semgrep_tool.transform_semgrep_output(raw_output, execution_time)

    assert result.success is True


@pytest.mark.unit
def test_semgrep_transform_output_actual():
    semgrep_tool = SemgrepTool()

    base_directory = Path(__file__).resolve().parent
    test_data_path = base_directory / "semgrep_actual.json"
    with open(test_data_path) as f:
        raw_output = f.read()

    execution_time = 0.0

    result = semgrep_tool.transform_semgrep_output(raw_output, execution_time)

    assert result.success is True
    assert len(result.parsed_findings) == 27
    assert result.rules_matched == 27
    assert result.files_scanned == 1
