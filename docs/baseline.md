# Phase 1 Baseline — Demo Pack A

**Last updated:** 2026-04-14
**Scenario:** `pack-a` (Vulnerable Python Flask service)
**Commit:** _[fill in after you commit — `git rev-parse --short HEAD`]_

## Headline

| Metric | Value |
|---|---|
| **Detection rate (recall)** | **100%** |
| **Precision** | **96.15%** |
| **F1** | **98.04%** |
| True positives | 50 |
| False positives | 2 |
| False negatives | 0 |
| Run duration (wall) | 67.9s |
| LLM token usage | 7,519 |
| Tools invoked | Semgrep, pip-audit |

The Phase 1 exit criterion is ≥80% detection rate on Demo Pack A. This baseline clears that bar.

## Sub-scores

**Code findings (Semgrep):** recall 100%, precision 84.6%, F1 91.7%. 11 true positives, 2 false positives, 0 false negatives, against 11 detectable manifest entries.

**Dependency findings (pip-audit):** recall 100%, precision 100%, F1 100%. 39 true positives, 0 false positives, 0 false negatives, against 39 detectable manifest entries covering 9 packages (including 4 incidental CVEs flagged as `planned: false` in the manifest but counted as true positives per the scoring contract).

## What the numbers represent

These figures measure the **full Phase 1 pipeline** end-to-end: `POST /api/v1/analyze` → deterministic planner → Semgrep (direct CLI) + pip-audit (via custom MCP server) → LLM synthesis → structured report. The test driving this baseline is `tests/scenario/test_pack_a_baseline.py`, which exercises the system via FastAPI's `TestClient` against the real agent.

Scoring is handled by `app/scoring/matcher.py` using a precision/recall rubric distinct from the agent's inline severity-weighted risk score. The scoring contract:

- **Denominator** is the count of `detectable: true` entries in `expected_findings.json`. Manifest entries marked `detectable: false` (e.g. `hardcoded-secret`, which Semgrep OSS cannot reliably detect without commercial rule packs) are excluded from both numerator and denominator. Two such entries exist for Pack A.
- **Incidental CVEs** (manifest entries with `planned: false`) are counted as true positives when detected. These represent real vulnerabilities the tool correctly flagged that weren't part of the original seeded set.
- **Dependency alias resolution** uses union-find across `PYSEC-*`, `CVE-*`, and `GHSA-*` identifiers so that the same vulnerability reported under different advisories collapses to a single true positive.

## Known limitations

**Precision is capped at 96.15% by a dedup limitation in the scoring layer, not by agent behavior.** Semgrep reports two vulnerabilities — the SQL injection at lines 102–103 and the SSRF at lines 113–114 — on both lines of their multi-line source spans. The current dedup in `matcher.py` collapses findings by `(file, line_start)`, which correctly handles the common case of multiple rules firing on the same line, but does not collapse findings reported at different positions within a single multi-line vulnerability. This produces 2 structural false positives that are not detection errors. Filed as a Phase 1.5 cleanup candidate: dedup by token span rather than line.

**Cost estimate is not currently populated** (`cost_estimate: 0` in the dumped baseline). The agent records token count correctly but does not yet compute `ReportMetadata.cost_estimate` from provider pricing. Filed as a Phase 1.5 cleanup candidate.

**Agent-reported duration under-counts wall-clock time** by roughly 42%. Wall clock: 67.9s. Agent-reported: 39.3s. The gap is almost certainly the LLM synthesis call sitting outside the agent's timing wrapper. Filed as a Phase 1.5 cleanup candidate.

None of these limitations affect the detection numbers, which come from the real agent pipeline against real Pack A inputs.

## Detectable-only scoring — what the manifest doesn't count

Two code-level vulnerabilities are seeded in Pack A but marked `detectable: false` in the manifest with explicit reasons:

- `CODE-012` (hardcoded DB password) — Semgrep OSS lacks generic secret detection; this requires commercial rule packs or a dedicated secret scanner.
- `CODE-013` (`yaml.load` without SafeLoader) — Semgrep's taint rules don't fire outside Flask route context for this pattern.

These are excluded from the denominator per the locked scoring contract. They represent a deliberate boundary of the OSS tool stack, not a failure of the agent. Phase 2's introduction of LLM-driven tool selection (Planner agent) and additional tools will revisit whether these become detectable under a richer tool set.

## How to reproduce

```bash
poetry run pytest tests/scenario/test_pack_a_baseline.py -s -m scenario
```

The test:
1. Hits `POST /api/v1/analyze` via FastAPI `TestClient` with `{"scenario_id": "pack-a"}`
2. Splits the returned `SecurityReport.findings` by `evidence.tool_name`
3. Extracts the raw pip-audit `DependencyScanResult` from `execution_plan.steps` for alias-graph construction
4. Calls `score_findings(...)` from `app/scoring/matcher.py`
5. Dumps the full run to `baselines/pack-a-{timestamp}.json`
6. Prints a one-line BASELINE summary and asserts detection thresholds

The test does not mock LLM calls or tool execution. Each run consumes real OpenAI credits and takes ~60–70 seconds.
