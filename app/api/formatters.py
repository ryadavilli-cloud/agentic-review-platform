from app.models.report import SecurityReport


def format_report_as_markdown(security_report: SecurityReport) -> str:
    """
    These are the steps for the formatter:
    1. Add header 1, and ascore summary
    2. Add summary header 2, and simple summary with themse.
    3. Add recommendations header 2,
    4. Add recommendations Header 3, for input validation.
    5. For each category. add category, impact and fix.
    6. add findings header 2, create table.
        for each finding - add sl no., title, severity, file, lines.
    """
    markdown_strings: list[str] = []
    markdown_strings.append("# Security Review Report")
    markdown_strings.append(f"Score: {security_report.score}")
    markdown_strings.append("\n## Summary")
    markdown_strings.append(f"{security_report.summary}")

    markdown_strings.append("\n## Recommendations:")
    for s in security_report.recommendation_groups:
        markdown_strings.append(f"\n### {s.theme}")
        markdown_strings.append(f"**Affected:** {', '.join(s.finding_titles)}")
        markdown_strings.append(f"**Impact:** {s.impact}")
        markdown_strings.append(f"**Fix:** {s.remediation}")

    markdown_strings.append("## Findings")
    markdown_strings.append("| # | Title | Severity | File | Line(s) |")
    markdown_strings.append("|---|-------|----------|------|---------|")
    for i, finding in enumerate(security_report.findings, start=1):
        markdown_strings.append(
            f"| {i} | {finding.title} | {finding.severity.name} |"
            f" {finding.evidence.file_path} | {finding.evidence.line_start} |"
        )

    if security_report.metadata:
        markdown_strings.append("\n## Metadata")
        markdown_strings.append(
            f"**Duration:** {security_report.metadata.duration_seconds:.1f}s"
        )
        markdown_strings.append(
            f"**Tools:** {', '.join(security_report.metadata.tools_used)}"
        )
        markdown_strings.append(f"**Tokens:** {security_report.metadata.token_count}")

    output_str = "\n".join(markdown_strings)
    return output_str
