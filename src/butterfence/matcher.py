"""Core matching engine - pure function, no side effects."""

from __future__ import annotations

from dataclasses import dataclass, field

from butterfence.cache import get_compiled_rules
from butterfence.entropy import find_high_entropy_strings
from butterfence.normalizer import normalize_command, split_commands
from butterfence.obfuscation import detect_obfuscation
from butterfence.rules import Action, CompiledRule, RuleMatch
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
            # Split compound commands and normalize each
            parts = split_commands(cmd)
            for part in parts:
                texts.append(normalize_command(part))
            # Also include the full original for pattern coverage
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


def _get_obfuscation_texts(texts: list[str]) -> list[str]:
    """Extract decoded text from obfuscation findings."""
    extra: list[str] = []
    for text in texts:
        findings = detect_obfuscation(text)
        for f in findings:
            if f.decoded_text and f.decoded_text != "<decode-failed>":
                extra.append(f.decoded_text)
    return extra


def _get_entropy_matches(texts: list[str], threshold: float) -> list[RuleMatch]:
    """Check for high-entropy strings that may be secrets."""
    matches: list[RuleMatch] = []
    for text in texts:
        findings = find_high_entropy_strings(text, threshold=threshold)
        for f in findings:
            matches.append(
                RuleMatch(
                    category="secret_exfil",
                    severity="high",
                    action="block",
                    pattern=f"entropy={f.entropy}",
                    matched_text=f.text[:200],
                )
            )
    return matches


def _is_safe_listed(text: str, rule: CompiledRule) -> bool:
    """Check if the text matches any safe-list pattern for this rule."""
    return any(sp.search(text) for sp in rule.safe_patterns)


def match_rules(payload: HookPayload, config: dict) -> MatchResult:
    """Match a hook payload against compiled rules. Pure function.

    Returns MatchResult with the highest-severity decision.
    """
    rules = get_compiled_rules(config)
    texts = _extract_matchable_text(payload)

    if not texts:
        return MatchResult(decision="allow")

    # Add decoded obfuscation text for matching
    obf_texts = _get_obfuscation_texts(texts)
    all_texts = texts + obf_texts

    # De-duplicate while preserving order
    seen: set[str] = set()
    unique_texts: list[str] = []
    for t in all_texts:
        if t not in seen:
            seen.add(t)
            unique_texts.append(t)

    all_matches: list[RuleMatch] = []
    highest_action = Action.ALLOW

    for rule in rules:
        for text in unique_texts:
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

    # Check entropy for Write/Edit content
    if payload.tool_name in ("Write", "Edit"):
        threshold = config.get("entropy_threshold", 4.5)
        entropy_matches = _get_entropy_matches(texts, threshold)
        for em in entropy_matches:
            all_matches.append(em)
            if _action_priority(Action.BLOCK) > _action_priority(highest_action):
                highest_action = Action.BLOCK

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
