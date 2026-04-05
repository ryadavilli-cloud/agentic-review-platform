from pydantic import BaseModel


class ExpectedCodeFinding(BaseModel):
    id: str
    tool: str
    type: str
    file: str
    line: int
    severity: str
    detectable: bool
    detectable_reason: str | None = None
    description: str | None = None


class ExpectedDependencyFinding(BaseModel):
    id: str
    tool: str
    package: str
    version: str
    cve: str
    severity: str
    detectable: bool
    planned: bool


class ExpectedFindings(BaseModel):
    version: str
    code_findings: list[ExpectedCodeFinding] = []
    dependency_findings: list[ExpectedDependencyFinding] = []


class MatchResult(BaseModel):
    expected_finding_id: str
    matched: bool
    actual_finding_id: str | None = None


class ScoreResult(BaseModel):
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0


class CodeScoreResult(BaseModel):
    score: ScoreResult
    matches: list[MatchResult] = []


class DependencyScoreResult(BaseModel):
    score: ScoreResult
    matches: list[MatchResult] = []


class CombinedScoreResult(BaseModel):
    code: CodeScoreResult
    dependency: DependencyScoreResult
    combined: ScoreResult
