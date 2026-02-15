"""Core matching engine - pure function, no side effects."""

from __future__ import annotations

from dataclasses import dataclass, field

from butterfence.rules import Action, CompiledRule, RuleMatch, compile_rules
from butterfence.utils import normalize_path


@dataclass
class HookPayload:
    hook_event: str  # "PreToolUse" / "PostToolUse"
    tool_name: str   # "Bash", "Read", "Write", "Edit"
    tool_input: dict  # {"command": "..."} or {"file_path": "..."}


@dataclass
class MatchResult:
    decision: str  # "block", "warn", "allow"
    matches: list[RuleMatch] = field(default_factory=list)
    reason: str = ""


def _extract_matchable_text(payload: HookPayload) -> list[str]:
    """Extract text strings to match against from a hook payload."""
    texts: list[str] = []
    tool = payload.tool_name

    if tool == "Bash":
        cmd = payload.tool_input.get("command", "")
        if cmd:
            texts.append(cmd)

    elif tool == "Read":
        fp = payload.tool_input.get("file_path", "")
        if fp:
            texts.append(normalize_path(fp))

    elif tool in ("Write", "Edit"):
        fp = payload.tool_input.get("file_path", "")
        if fp:
            texts.append(normalize_path(fp))
        content = payload.tool_input.get("content", "")
        if content:
            texts.append(content)
        new_string = payload.tool_input.get("new_string", "")
        if new_string:
            texts.append(new_string)

    return texts


def _is_safe_listed(text: str, rule: CompiledRule) -> bool:
    """Check if the text matches any safe-list pattern for this rule."""
    return any(sp.search(text) for sp in rule.safe_patterns)


def match_rules(payload: HookPayload, config: dict) -> MatchResult:
    """Match a hook payload against compiled rules. Pure function.

    Returns MatchResult with the highest-severity decision.
    """
    rules = compile_rules(config)
    texts = _extract_matchable_text(payload)

    if not texts:
        return MatchResult(decision="allow")

    all_matches: list[RuleMatch] = []
    highest_action = Action.ALLOW

    for rule in rules:
        for text in texts:
            if rule.pattern.search(text) and not _is_safe_listed(text, rule):
                match = RuleMatch(
                    category=rule.category,
                    severity=rule.severity.value,
                    action=rule.action.value,
                    pattern=rule.raw_pattern,
                    matched_text=text[:200],
                )
                all_matches.append(match)
                if _action_priority(rule.action) > _action_priority(highest_action):
                    highest_action = rule.action

    if not all_matches:
        return MatchResult(decision="allow")

    reasons = []
    for m in all_matches:
        reasons.append(f"[{m.severity}:{m.category}] matched pattern: {m.pattern}")

    return MatchResult(
        decision=highest_action.value,
        matches=all_matches,
        reason="; ".join(reasons),
    )


def _action_priority(action: Action) -> int:
    """Higher number = more restrictive action."""
    return {Action.ALLOW: 0, Action.WARN: 1, Action.BLOCK: 2}[action]
