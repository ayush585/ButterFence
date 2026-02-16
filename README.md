# ButterFence

**Claude Code-native safety harness** that red-teams repos against destructive/secret-leaking agent behavior and auto-generates enforceable Claude Code hooks to prevent it.

[![PyPI](https://img.shields.io/pypi/v/butterfence.svg)](https://pypi.org/project/butterfence/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-315%20passing-brightgreen.svg)]()

<img width="1918" height="707" alt="butterfence" src="https://github.com/user-attachments/assets/0ffea870-c53b-430c-8a4a-21fcb46e85dc" />

---

## What It Does

1. **Init** - Installs safety hooks into Claude Code that intercept dangerous tool calls in real-time
2. **Audit** - Runs 44 red-team scenarios covering 11 threat categories
3. **Red Team** - Uses **Claude Opus 4.6 as an adversary** to generate novel, repo-specific attack scenarios and test them against your defenses
4. **Scan** - Proactively scans repos for secrets, dangerous files, and high-entropy strings
5. **Report** - Generates scored safety reports in Markdown, HTML, JSON, SARIF, or JUnit
6. **Watch** - Live terminal dashboard monitoring all hook events in real-time
7. **CI** - CI/CD integration with pass/fail exit codes and GitHub Actions workflow generation
8. **Explain** - Educational threat explanations for every scenario
9. **Packs** - Community rule packs for OWASP, AWS, Docker, Node.js, Python, and more

---

## Quickstart

```bash
# Install from PyPI
pip install butterfence

# Initialize ButterFence in your project
butterfence init

# Run the red-team audit (44 scenarios)
butterfence audit

# Scan for secrets in your repo
butterfence scan

# Generate a full safety report
butterfence report --format html --output report.html

# Save your Anthropic API key securely (one-time)
butterfence auth

# AI Red Team: Claude Opus 4.6 attacks, ButterFence defends
butterfence redteam --count 10

# Start live monitoring
butterfence watch
```

---

## AI Red Team (Powered by Opus 4.6)

The `butterfence redteam` command turns Claude Opus 4.6 into an adversary. It scans your repo's structure, tech stack, and sensitive files, then asks the model to think like a red-team hacker and generate creative attacks targeting YOUR specific codebase. Every generated scenario is run through the same matcher as live hooks.

```bash
# Install the Anthropic SDK (optional dependency)
pip install anthropic

# Save your API key securely (one-time setup)
butterfence auth

# Run AI red-team with 10 attack scenarios
butterfence redteam --count 10

# Focus on specific categories
butterfence redteam --categories docker_escape,supply_chain

# Save results and generate report
butterfence redteam --save --report

# Auto-fix: Opus 4.6 attacks, finds gaps, then patches the defense
butterfence redteam --fix
```

**What makes it powerful:**
- Opus 4.6 generates attacks **tailored to your repo** (uses your file tree, tech stack, languages)
- Tries obfuscation, variable indirection, base64 encoding, and creative evasion
- Results scored identically to the built-in audit (same matcher, same scoring engine)
- Discovers gaps in your rules that static scenarios can't find
- **`--fix` mode**: When attacks get through, Opus 4.6 analyzes the gaps and generates exact regex patterns to close them
- **`--verify` mode**: Full closed loop in one command — attack, patch, re-attack, show improvement

---

## API Key Management

ButterFence stores your Anthropic API key securely in your home directory with restricted file permissions. The key is never stored in your project repo.

```bash
# Save your key (interactive, hidden input)
butterfence auth

# Or pass directly
butterfence auth --key sk-ant-your-key-here

# Check status (shows masked key)
butterfence auth --status

# Securely remove (zero-overwrites before deletion)
butterfence auth --remove
```

**Security:**
- Stored at `~/.butterfence/api_key` (never in project directory)
- File permissions: owner-only (0600 on Unix, restricted ACL on Windows)
- Secure deletion: file content overwritten with null bytes before unlinking
- Key validation: format checked before saving
- Display masking: only first 7 + last 4 characters shown

**Lookup order:** Environment variable > Stored key file

---

## How It Works

### Hook System

ButterFence registers as Claude Code hooks in `.claude/settings.local.json`. When Claude Code attempts to use tools (Bash, Read, Write, Edit), the hook intercepts the call and checks it against security rules:

- **Block**: Dangerous action denied with explanation
- **Warn**: Suspicious action prompts user confirmation
- **Allow**: Safe action proceeds normally

### Advanced Detection

Beyond simple regex matching, ButterFence v2 includes:

- **Command Normalization** - Collapses whitespace, splits compound commands for thorough matching
- **Obfuscation Detection** - Catches base64-encoded commands, hex escapes, variable indirection, backtick substitution
- **Shannon Entropy Analysis** - Detects high-entropy strings in written content that may be secrets/tokens
- **Behavioral Chain Detection** - Tracks multi-step attack patterns across events (e.g., read `.env` then `curl POST` = exfiltration)
- **Rule Compilation Cache** - Caches compiled rules by config hash for performance
- **False-positive safe mode (Docs-aware entropy)** - Entropy-based detection is powerful but can over-trigger on random-looking text. ButterFence automatically treats entropy-only findings as WARN when writing documentation files (.md, docs/), while still BLOCKING known credential formats (AWS/GitHub/Slack/etc.). This keeps docs workflows smooth without sacrificing secret protection.

### 11 Defense Categories

| Category | What It Catches |
|----------|----------------|
| `destructive_shell` | `rm -rf /`, `mkfs`, `chmod 777`, disk wipe, shutdown |
| `secret_access` | Reading `.env`, SSH keys, AWS credentials, certificates |
| `secret_exfil` | Writing API keys, echoing secrets to logs |
| `risky_git` | Force push, hard reset, destructive clean |
| `network_exfil` | Posting files via curl, reverse shells, nc/socat |
| `python_dangerous` | `subprocess` shell=True, `eval()`, `exec()`, `pickle.loads()` |
| `sql_injection` | f-string SQL queries, `DROP TABLE`, `DROP DATABASE` |
| `docker_escape` | `--privileged`, mount root, `--pid=host`, docker.sock |
| `cloud_credentials` | Azure/GCP/AWS secrets, `gcloud`/`az` token extraction |
| `supply_chain` | pip HTTP registry, `curl\|sh`, `wget\|python`, npm HTTP |
| `privilege_escalation` | `sudo su`, chmod setuid, `chown root`, `nsenter` |

### Scoring

- **100/100 (A)**: Hardened - all threats blocked
- **70-89 (B)**: Mostly safe, some gaps
- **50-69 (C)**: Risky, needs attention
- **<50 (F)**: Unsafe for autonomy

---

## Commands

| Command | Description |
|---------|-------------|
| `butterfence init` | Initialize ButterFence (create config, install hooks) |
| `butterfence audit` | Run 44 red-team scenarios |
| `butterfence audit --quick` | Critical scenarios only |
| `butterfence audit --report` | Audit + generate report |
| `butterfence audit --category <name>` | Filter by category |
| `butterfence report` | Generate safety report (Markdown) |
| `butterfence report --format html` | HTML report (self-contained) |
| `butterfence report --format sarif` | SARIF 2.1.0 for GitHub Code Scanning |
| `butterfence report --format junit` | JUnit XML for CI pipelines |
| `butterfence report --format json` | Structured JSON export |
| `butterfence scan` | Scan repo for secrets and security issues |
| `butterfence scan --format json` | JSON output |
| `butterfence scan --format sarif` | SARIF output |
| `butterfence scan --fix` | Show remediation suggestions |
| `butterfence watch` | Live event monitoring dashboard |
| `butterfence ci --min-score 80` | CI mode with exit codes |
| `butterfence ci --format sarif --output results.sarif` | CI with SARIF output |
| `butterfence ci --badge badge.svg` | Generate SVG score badge |
| `butterfence ci --generate-workflow` | Generate GitHub Actions workflow |
| `butterfence auth` | Save API key securely (interactive prompt) |
| `butterfence auth --status` | Check API key configuration |
| `butterfence auth --remove` | Securely delete stored key |
| `butterfence redteam` | AI red-team with Opus 4.6 (10 scenarios) |
| `butterfence redteam --count 20` | Generate 20 attack scenarios |
| `butterfence redteam --categories <list>` | Focus on specific categories |
| `butterfence redteam --save --report` | Save JSON results + generate report |
| `butterfence redteam --fix` | Auto-fix gaps with AI-suggested patterns |
| `butterfence redteam --verify` | Full loop: attack, fix, verify improvement |
| `butterfence policy --add "..."` | Add a natural language security policy |
| `butterfence policy --list` | List current policies |
| `butterfence policy --check` | Evaluate policies with Opus 4.6 |
| `butterfence analytics` | Event log analytics and trends |
| `butterfence analytics --period 24h` | Filter by time period |
| `butterfence explain <id>` | Educational threat explanation |
| `butterfence configure` | Interactive configuration wizard |
| `butterfence pack list` | List available rule packs |
| `butterfence pack install <name>` | Install a rule pack |
| `butterfence pack info <name>` | Show pack details |
| `butterfence uninstall` | Remove hooks |
| `butterfence uninstall --remove-data` | Remove hooks + all data |
| `butterfence status` | Show current ButterFence state |

---

## CI/CD Integration

### GitHub Actions

```bash
# Auto-generate a workflow file
butterfence ci --generate-workflow
```

This creates `.github/workflows/butterfence.yml` that:
1. Installs ButterFence
2. Runs the security audit
3. Uploads SARIF results to GitHub Security tab

### Manual CI

```bash
# Exit code 0 if score >= 80, exit code 1 otherwise
butterfence ci --min-score 80 --format sarif --output results.sarif

# Generate a badge for your README
butterfence ci --badge badge.svg
```

---

## Community Rule Packs

ButterFence ships with 7 built-in rule packs:

| Pack | Description |
|------|-------------|
| `owasp` | OWASP Top 10 patterns (XSS, command injection, path traversal) |
| `aws` | AWS credential and dangerous operation patterns |
| `cloud_security` | Multi-cloud security (Azure, GCP, AWS) |
| `nodejs` | Node.js security (eval, child_process, prototype pollution) |
| `python` | Python security (subprocess, pickle, eval, exec) |
| `docker` | Container escape and dangerous Docker patterns |
| `supply_chain` | Dependency confusion and script injection |

```bash
# List available packs
butterfence pack list

# Install a pack
butterfence pack install aws

# View pack details
butterfence pack info owasp
```

---

## Configuration

After `butterfence init`, the config lives at `.butterfence/config.json`. You can:

- Enable/disable categories
- Change severity levels (critical/high/medium/low)
- Change actions (block/warn/allow)
- Add custom patterns
- Add safe-list patterns for known-safe commands
- Set entropy detection threshold
- Define behavioral attack chains
- Install community rule packs

Use the interactive wizard:

```bash
butterfence configure
```

---

## Live Dashboard

```bash
butterfence watch
```

```
+---------------- ButterFence Live Monitor ----------------+
| Live Event Feed              | Blocks: 42  Warns: 7     |
| [12:01:03] BLOCK rm -rf /    | Allows: 156              |
| [12:01:05] ALLOW git status  | Events/min: 12.3         |
| [12:01:08] BLOCK cat .env    |                           |
|                              | Categories:               |
|                              | shell:  ████████  15      |
|                              | secret: ████      8       |
|                              |                           |
|                              | Top Rules:                |
|                              | rm -rf: 15                |
|                              | .env:   8                 |
+----------------------------------------------------------+
| Risk Score: 85/100 (B)                   Press 'q' quit  |
+----------------------------------------------------------+
```

---

## Architecture

```
src/butterfence/
    cli.py                  # Typer CLI (14 commands + pack sub-app)
    config.py               # Config loading, validation, defaults (11 categories)
    rules.py                # Rule enums, compilation
    matcher.py              # Core matching engine (pure function)
    hook_runner.py          # Claude Code hook entry point
    installer.py            # Hook installation into settings.local.json
    audit.py                # Red-team scenario runner (44 scenarios)
    scoring.py              # Severity-weighted scoring
    report.py               # Markdown report generator
    utils.py                # Path normalization, JSON helpers
    entropy.py              # Shannon entropy secret detection
    normalizer.py           # Command normalization
    obfuscation.py          # Base64/hex/variable obfuscation detection
    chain_detector.py       # Multi-step behavioral attack chain detection
    cache.py                # Rule compilation cache
    log_rotation.py         # Log file rotation
    migration.py            # Config schema versioning (v1 -> v2)
    scanner.py              # Proactive repo secret scanner
    watcher.py              # Live terminal dashboard
    ci.py                   # CI/CD integration
    analytics.py            # Event log analytics
    explainer.py            # Educational threat explanations
    configure.py            # Interactive config wizard
    packs.py                # Community rule pack manager
    redteam.py              # AI red-team via Opus 4.6 API
    auth.py                 # Secure API key management
    policy.py               # Natural language policy evaluation (Opus 4.6)
    exporters/
        sarif.py            # SARIF 2.1.0 format
        junit.py            # JUnit XML format
        json_export.py      # JSON export
        html_report.py      # Self-contained HTML report
        badge.py            # SVG shield badge
assets/
    scenarios.yaml          # 44 red-team scenarios with explanations
    packs/                  # 7 built-in rule packs
```

The matcher is a **pure function** shared between live hooks and audit simulation, ensuring audit results match real hook behavior.

---

## Testing

```bash
# Run all 315 tests
pytest tests/

# Run specific test file
pytest tests/test_matcher.py -v

# Run with coverage
pytest tests/ --cov=butterfence
```

**315 tests** covering all modules: matcher, config, rules, audit, scoring, entropy, normalizer, obfuscation, chain detection, cache, log rotation, migration, scanner, watcher, CI, analytics, explainer, packs, exporters, redteam, and CLI integration.

---

## Dependencies

| Dependency | Purpose |
|------------|---------|
| `typer>=0.12` | CLI framework |
| `rich>=13` | Terminal UI, tables, panels, live dashboard |
| `pyyaml>=6` | YAML scenario/pack loading |
| `pathspec>=0.11` | `.gitignore` pattern matching for scanner |
| `anthropic>=0.39` | *Optional* - Anthropic SDK for `redteam` command |

---

## License

MIT

## Built With

Built entirely with **Claude Code** powered by **Claude Opus 4.6** during the Cerebral Valley hackathon (Feb 10-16, 2026). ButterFence uses Opus 4.6 in three creative ways: as a red-team attacker, as a defense patcher, and as a natural language policy evaluator.

