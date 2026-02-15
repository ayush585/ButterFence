"""Markdown report generator."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from butterfence.scoring import ScoreResult


def generate_report(
    score_result: ScoreResult,
    audit_results: list[dict],
    output_path: Path | None = None,
) -> str:
    """Generate a structured markdown safety report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# ButterFence Safety Report",
        "",
        f"**Generated:** {now}",
        "",
        "---",
        "",
        "## Score",
        "",
        f"**{score_result.total_score}/{score_result.max_score}** | Grade: **{score_result.grade}** ({score_result.grade_label})",
        "",
    ]

    # Score badge
    if score_result.total_score >= 90:
        lines.append("> Your repo is **hardened** against common agent threats.")
    elif score_result.total_score >= 70:
        lines.append("> Your repo is **mostly safe** but has some gaps to address.")
    elif score_result.total_score >= 50:
        lines.append("> Your repo has **significant risks** that need attention.")
    else:
        lines.append("> Your repo is **unsafe for autonomous agent use**. Immediate action required.")
    lines.append("")

    # Results table
    lines.extend([
        "---",
        "",
        "## Scenario Results",
        "",
        "| Status | ID | Name | Category | Severity | Expected | Actual |",
        "|--------|----|------|----------|----------|----------|--------|",
    ])

    for r in audit_results:
        status = "PASS" if r.get("passed", False) else "FAIL"
        lines.append(
            f"| {status} | {r['id']} | {r['name']} | {r['category']} | "
            f"{r['severity']} | {r['expected_decision']} | {r['actual_decision']} |"
        )
    lines.append("")

    # Deductions
    if score_result.deductions:
        lines.extend([
            "---",
            "",
            "## Deductions",
            "",
            "| Scenario | Category | Severity | Points | Reason |",
            "|----------|----------|----------|--------|--------|",
        ])
        for d in score_result.deductions:
            lines.append(
                f"| {d['scenario']} | {d['category']} | {d['severity']} | "
                f"{d['points']} | {d.get('reason', 'Scenario failed')} |"
            )
        lines.append("")

    # Category coverage
    lines.extend([
        "---",
        "",
        "## Category Coverage",
        "",
        "| Category | Total | Passed | Failed |",
        "|----------|-------|--------|--------|",
    ])
    for cat, stats in score_result.category_coverage.items():
        lines.append(
            f"| {cat} | {stats['total']} | {stats['passed']} | {stats['failed']} |"
        )
    lines.append("")

    # Recommendations
    lines.extend([
        "---",
        "",
        "## Recommendations",
        "",
    ])
    for rec in score_result.recommendations:
        lines.append(f"- {rec}")
    lines.append("")

    report_text = "\n".join(lines)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_text, encoding="utf-8")

    return report_text
