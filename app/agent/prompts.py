from app.models.agent import ExecutionPlan
from app.models.finding import Finding
from app.models.review import ReviewRequest

SYNTHESIS_SYSTEM_PROMPT = """
Role Definition: 
You are a security review synthesizer. 
You receive findings from automated scanning tools and 
produce an executive-level assessment.

What you will receive:
Structured findings from code analysis (Semgrep) and dependency scanning (pip-audit),
 along with context about the reviewed target.

What you should produce:
A JSON object with the following fields:
- summary: A concise summary of the overall security posture.
- recommendation_groups: covers all input findings, none dropped. Ordered by severity 
                        of the most critical finding in the group
                        Each group has a theme (short label), 
                        finding_titles (list referencing input findings by titles),
                        impact (exploitation context from LLM knowledge),
                        remediation (specific fix guidance)
You must not invent findings absent from the input
If zero findings provided, return a single group with theme
"No Issues Detected" and general best-practice guidance
Here is an example of the expected output format:
{
  "summary": "2-4 sentence overall security assessment. References the most 
    critical issues. States deployment readiness.",

  "recommendation_groups": [
    {
      "theme": "Input Validation",
      "finding_titles": ["SQL injection in user search", 
                        "Command injection in ping endpoint"],
      "impact": "Why this group of issues matters, how they can be exploited together.",
      "remediation": "Specific fix pattern with code examples where applicable."
    }
  ]
}

Behavioral constraints:
Never invent findings not present in the input
Group related findings by theme rather than repeating similar advice
Order groups by severity of the most critical finding in each group
Reference specific files and line numbers in remediation guidance
Use your security domain knowledge to explain impact and provide specific fix patterns
Keep the summary to 2-4 sentences
If no findings are provided, state that no issues were detected

Format constraint: Respond with raw JSON only. 
                    No markdown fences, no preamble, 
                    no explanation outside the JSON structure.
"""


def serialize_findings_for_llm(findings: list[Finding]) -> str:
    parts: list[str] = []

    if not findings:
        return "No findings were detected by the automated tools."

    for i, finding in enumerate(findings, start=1):
        parts.append(f"Finding {i}:")
        parts.append(f"Title: {finding.title}")
        parts.append(f"Severity: {finding.severity.name}")
        parts.append(f"Category: {finding.category.name}")

        if finding.evidence.file_path:
            strtemp = f"File: {finding.evidence.file_path}"
            str_lines = "Line"
            if (
                finding.evidence.line_start is not None
                and finding.evidence.line_end is not None
            ):
                if finding.evidence.line_start == finding.evidence.line_end:
                    str_lines += f": {finding.evidence.line_start}"
                else:
                    str_lines = f"Lines: {finding.evidence.line_start}"
                    str_lines += f" - {finding.evidence.line_end}"
                strtemp += f", {str_lines}"
            elif (
                finding.evidence.line_start is None
                and finding.evidence.line_end is None
            ):
                str_lines = ""
            elif finding.evidence.line_start is not None:
                str_lines = f"Line: {finding.evidence.line_start}"
                strtemp += f", {str_lines}"
            elif finding.evidence.line_end is not None:
                str_lines = f"Line: {finding.evidence.line_end}"
                strtemp += f", {str_lines}"
            parts.append(strtemp)
        if finding.evidence.code_snippet:
            parts.append(f"Code Snippet: {finding.evidence.code_snippet}")
        if finding.evidence.tool_name:
            parts.append(f"Tool: {finding.evidence.tool_name}")

        parts.append("")

    return "\n".join(parts)


def build_user_prompt(
    findings: list[Finding], request: ReviewRequest, execution_plan: ExecutionPlan
) -> str:
    """
    Build the user prompt for the synthesis LLM,
    incorporating findings and context.
    """
    prompt_parts: list[str] = []

    prompt_parts.append("Review Context:")
    if request.local_path is None and request.repository_url is None:
        prompt_parts.append(" - Code Snippet Review")
    if request.local_path is not None:
        prompt_parts.append(f"Local Path: {request.local_path}")
    if request.repository_url is not None:
        prompt_parts.append(f"Repository URL: {request.repository_url}")

    prompt_parts.append("Tools that were executed:")
    for step in execution_plan.steps:
        prompt_parts.append(f"Step: {step.step_number} : {step.tool_name}")
        prompt_parts.append(f"Status: {step.status.name}")

    prompt_parts.append(f"Findings count : {len(findings)}")

    prompt_parts.append(f"Finding Details: {serialize_findings_for_llm(findings)}")

    return "\n".join(prompt_parts)
