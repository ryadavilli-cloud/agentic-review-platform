from collections import defaultdict
from dataclasses import dataclass

from app.models.finding import Finding
from app.scoring.models import (
    CodeScoreResult,
    CombinedScoreResult,
    DependencyScoreResult,
    ExpectedFindings,
    MatchResult,
    ScoreResult,
)
from app.tools.pip_audit_results import DependencyScanResult


def _safe_file_path(finding: Finding) -> str:
    return finding.evidence.file_path or ""


def _safe_line_start(finding: Finding) -> int | None:
    return finding.evidence.line_start


def _safe_raw_output(finding: Finding) -> str:
    return finding.evidence.raw_output or ""


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lower()


def _path_matches(actual_path: str, expected_file: str) -> bool:
    actual = _normalize_path(actual_path)
    expected = _normalize_path(expected_file)
    return actual.endswith(expected)


def _compute_score(tp: int, fp: int, fn: int) -> ScoreResult:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return ScoreResult(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def _dedup_code_findings_by_line(findings: list[Finding]) -> list[Finding]:
    """
    Dedup Semgrep-style findings by (normalized file path, line_start).
    If multiple rules fire on the same line, keep only the first.
    Findings with no line_start are kept individually.
    """
    seen: set[tuple[str, int]] = set()
    deduped: list[Finding] = []

    for finding in findings:
        line_start = _safe_line_start(finding)
        file_path = _normalize_path(_safe_file_path(finding))

        if line_start is None:
            deduped.append(finding)
            continue

        key = (file_path, line_start)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)

    return deduped


def match_code_findings(
    manifest: ExpectedFindings,
    actual_findings: list[Finding],
    *,
    line_tolerance: int = 3,
) -> CodeScoreResult:
    expected_code_findings = [
        finding for finding in manifest.code_findings if finding.detectable
    ]
    deduped_actual = _dedup_code_findings_by_line(actual_findings)

    used_actual_indexes: set[int] = set()
    match_results: list[MatchResult] = []
    true_positives = 0

    for expected in expected_code_findings:
        matched_index: int | None = None

        for index, actual in enumerate(deduped_actual):
            if index in used_actual_indexes:
                continue

            actual_path = _safe_file_path(actual)
            actual_line = _safe_line_start(actual)

            if actual_line is None:
                continue

            if not _path_matches(actual_path, expected.file):
                continue

            if abs(actual_line - expected.line) <= line_tolerance:
                matched_index = index
                break

        if matched_index is not None:
            used_actual_indexes.add(matched_index)
            true_positives += 1
            match_results.append(
                MatchResult(
                    expected_finding_id=expected.id,
                    matched=True,
                    actual_finding_id=str(deduped_actual[matched_index].id),
                )
            )
        else:
            match_results.append(
                MatchResult(
                    expected_finding_id=expected.id,
                    matched=False,
                    actual_finding_id=None,
                )
            )

    false_negatives = len(expected_code_findings) - true_positives
    false_positives = len(deduped_actual) - len(used_actual_indexes)

    score = _compute_score(true_positives, false_positives, false_negatives)

    return CodeScoreResult(
        matches=match_results,
        score=score,
    )


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, item: str) -> None:
        if item not in self.parent:
            self.parent[item] = item

    def find(self, item: str) -> str:
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, a: str, b: str) -> None:
        self.add(a)
        self.add(b)
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a != root_b:
            self.parent[root_b] = root_a


def _build_alias_lookup(raw_scan: DependencyScanResult) -> dict[str, frozenset[str]]:
    """
    Builds alias groups so that IDs like:
      PYSEC-2023-221, CVE-2023-46136, GHSA-hrfv-mqp8-q5rw
    all map to the same canonical group.
    """
    uf = _UnionFind()

    for dependency in raw_scan.dependencies:
        for vuln in dependency.vulns:
            ids = {vuln.id, *vuln.aliases}
            ids = {value for value in ids if value}

            if not ids:
                continue

            id_list = list(ids)
            first = id_list[0]
            uf.add(first)

            for other in id_list[1:]:
                uf.union(first, other)

    grouped: dict[str, set[str]] = defaultdict(set)

    for item in uf.parent:
        root = uf.find(item)
        grouped[root].add(item)

    alias_lookup: dict[str, frozenset[str]] = {}
    for group in grouped.values():
        frozen_group = frozenset(group)
        for item in group:
            alias_lookup[item] = frozen_group

    return alias_lookup


@dataclass(frozen=True)
class _ActualDependencyGroup:
    canonical_ids: frozenset[str]
    representative_finding: Finding


def _dedup_dependency_findings(
    actual_findings: list[Finding],
    alias_lookup: dict[str, frozenset[str]],
) -> list[_ActualDependencyGroup]:
    """
    Dedup actual dependency findings by alias group.
    If an actual finding's raw_output is not in alias_lookup, treat it as its own group.
    """
    seen_groups: set[frozenset[str]] = set()
    deduped: list[_ActualDependencyGroup] = []

    for finding in actual_findings:
        raw_id = _safe_raw_output(finding)
        group = alias_lookup.get(raw_id, frozenset({raw_id}))

        if group not in seen_groups:
            seen_groups.add(group)
            deduped.append(
                _ActualDependencyGroup(
                    canonical_ids=group,
                    representative_finding=finding,
                )
            )

    return deduped


def match_dependency_findings(
    manifest: ExpectedFindings,
    actual_findings: list[Finding],
    raw_scan: DependencyScanResult,
) -> DependencyScoreResult:
    expected_deps = [f for f in manifest.dependency_findings if f.detectable]
    alias_lookup = _build_alias_lookup(raw_scan)
    deduped_actual = _dedup_dependency_findings(actual_findings, alias_lookup)

    used_actual_indexes: set[int] = set()
    match_results: list[MatchResult] = []
    true_positives = 0

    for expected in expected_deps:
        matched_index: int | None = None

        for index, actual_group in enumerate(deduped_actual):
            if index in used_actual_indexes:
                continue

            if expected.cve in actual_group.canonical_ids:
                matched_index = index
                break

        if matched_index is not None:
            used_actual_indexes.add(matched_index)
            true_positives += 1
            match_results.append(
                MatchResult(
                    expected_finding_id=expected.id,
                    matched=True,
                    actual_finding_id=str(
                        deduped_actual[matched_index].representative_finding.id
                    ),
                )
            )
        else:
            match_results.append(
                MatchResult(
                    expected_finding_id=expected.id,
                    matched=False,
                    actual_finding_id=None,
                )
            )

    false_negatives = len(expected_deps) - true_positives
    false_positives = len(deduped_actual) - len(used_actual_indexes)

    score = _compute_score(true_positives, false_positives, false_negatives)

    return DependencyScoreResult(
        matches=match_results,
        score=score,
    )


def score_findings(
    manifest: ExpectedFindings,
    code_findings: list[Finding],
    dep_findings: list[Finding],
    raw_scan: DependencyScanResult,
    *,
    line_tolerance: int = 3,
) -> CombinedScoreResult:
    code_score = match_code_findings(
        manifest,
        code_findings,
        line_tolerance=line_tolerance,
    )
    dependency_score = match_dependency_findings(
        manifest,
        dep_findings,
        raw_scan,
    )
    combined_score = _compute_score(
        code_score.score.true_positives + dependency_score.score.true_positives,
        code_score.score.false_positives + dependency_score.score.false_positives,
        code_score.score.false_negatives + dependency_score.score.false_negatives,
    )

    return CombinedScoreResult(
        code=code_score,
        dependency=dependency_score,
        combined=combined_score,
    )
