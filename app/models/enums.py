from enum import Enum

ReviewType = Enum("ReviewType", ["security", "risk", "comprehensive"])
AnalysisStatus = Enum(
    "AnalysisStatus", ["pending", "planning", "analyzing", "completed", "failed"]
)
Severity = Enum("Severity", ["critical", "high", "medium", "low", "info"])
FindingCategory = Enum(
    "FindingCategory", ["vulnerability", "dependency", "configuration", "code_quality"]
)
StepStatus = Enum("StepStatus", ["planned", "running", "complete", "failed", "skipped"])
