"""Severity-weighted scoring engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from butterfence.rules import SEVERITY_WEIGHTS, Severity


@dataclass
class ScoreResult:
    total_score: int
    max_score: int
    grade: str
    grade_label: str
    deductions: list[dict] = field(default_factory=list)
    category_coverage: dict[str, dict] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


def calculate_score(audit_results: list[dict], config: dict) -> ScoreResult:
    """Calculate a severity-weighted score from audit results.

    Each failed scenario deducts points based on its severity:
    critical=-15, high=-10, medium=-5, low=-2

    Score starts at 100.
    """
    max_score = 100
    total_deduction = 0
    deductions: list[dict] = []
    category_stats: dict[str, dict] = {}

    for result in audit_results:
        cat = result.get("category", "unknown")
        passed = result.get("passed", False)
        severity = result.get("severity", "high")

        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "passed": 0, "failed": 0}
        category_stats[cat]["total"] += 1

        if passed:
            category_stats[cat]["passed"] += 1
        else:
            category_stats[cat]["failed"] += 1
            sev = Severity(severity)
            weight = SEVERITY_WEIGHTS[sev]
            total_deduction += weight
            deductions.append({
                "scenario": result.get("id", "unknown"),
                "name": result.get("name", "unknown"),
                "category": cat,
                "severity": severity,
                "points": -weight,
                "reason": result.get("reason", ""),
            })

    score = max(0, max_score - total_deduction)
    grade, grade_label = _assign_grade(score)

    recommendations = _generate_recommendations(category_stats, deductions)

    return ScoreResult(
        total_score=score,
        max_score=max_score,
        grade=grade,
        grade_label=grade_label,
        deductions=deductions,
        category_coverage=category_stats,
        recommendations=recommendations,
    )


def _assign_grade(score: int) -> tuple[str, str]:
    """Assign a letter grade and label based on score."""
    if score >= 90:
        return "A", "Hardened"
    elif score >= 70:
        return "B", "Mostly Safe"
    elif score >= 50:
        return "C", "Risky"
    else:
        return "F", "Unsafe for Autonomy"


def _generate_recommendations(
    category_stats: dict[str, dict], deductions: list[dict]
) -> list[str]:
    """Generate actionable recommendations based on failures."""
    recs: list[str] = []
    failed_categories = {d["category"] for d in deductions}

    if "destructive_shell" in failed_categories:
        recs.append("Tighten destructive shell command patterns - consider blocking all `rm -rf` outside safe-listed directories")
    if "secret_access" in failed_categories:
        recs.append("Review secret file access rules - ensure all credential file patterns are covered")
    if "secret_exfil" in failed_categories:
        recs.append("Add patterns for additional secret formats (API keys, tokens) in your environment")
    if "risky_git" in failed_categories:
        recs.append("Enable branch protection and block all force-push operations")
    if "network_exfil" in failed_categories:
        recs.append("Block outbound data transfer commands that reference local files or environment variables")

    if not deductions:
        recs.append("All scenarios passed! Consider adding custom scenarios for your specific project risks")

    return recs
