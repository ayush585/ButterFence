# Demo Video Script (3 min)

## Setup

- Dark terminal, large font (18-20pt), high contrast
- Resolution: 1920x1080 or higher
- Record with OBS, Loom, or screen recorder
- Run: butterfence auth (to save your API key securely)
- Pre-run: butterfence init --no-hooks --dir demo/vulnerable-repo
- Test: butterfence redteam --dir demo/vulnerable-repo --count 5 (to verify timing)

---

## [0:00 - 0:20] THE HOOK (Problem Statement)

**On screen:** Empty terminal.

**Voiceover:**

> "AI coding agents can now run shell commands, read files, write code,
> and push to git. But what happens when they try to delete your
> filesystem, leak your secrets, or force-push to production?
> Nobody has solved this for Claude Code. Until now."

**Run:** `butterfence --version`

*The ASCII banner appears with "Claude Code Safety Harness v0.3.0"*

---

## [0:20 - 0:40] INITIALIZE (Quick Setup)

**Voiceover:**

> "ButterFence installs in one command. It hooks directly into Claude
> Code and intercepts every tool call in real-time."

**Run:**
```
cd demo/vulnerable-repo
butterfence init
```

*Show output: 11 categories, pattern count, hooks installed.*

> "That's it. 11 defense categories, dozens of patterns, hooks active.
> Let's see what this repo looks like."

---

## [0:40 - 1:05] THE LIVE BLOCK (Visceral Moment)

**Voiceover:**

> "This demo repo has intentionally dangerous code — hardcoded API keys,
> deployment scripts with curl-pipe-bash, privileged Docker containers.
> Let's see what ButterFence finds."

**Run:** `butterfence scan --dir .`

*Colored table of scan findings appears — secrets, dangerous files.*

> "ButterFence found secrets, dangerous scripts, and high-entropy tokens
> across the repo. And every dangerous action gets blocked live, with a
> clear explanation of why."

---

## [1:05 - 1:30] THE AUDIT (44 Scenarios)

**Voiceover:**

> "ButterFence ships with 44 red-team scenarios covering 11 threat
> categories — from destructive shell commands to Docker escapes to
> supply chain attacks."

**Run:** `butterfence audit`

*Rich table fills in — all 44 green PASS. Score: 100/100 Grade A "Hardened".*

> "44 for 44. Score: 100 out of 100. Grade A — Hardened. Every
> destructive command, every secret access, every exfiltration
> attempt — blocked."

*Pause 2-3 seconds to let the table sink in.*

---

## [1:30 - 2:15] THE WOW MOMENT: AI RED TEAM (Opus 4.6)

**Voiceover:**

> "But here's where it gets interesting. Those 44 scenarios are static.
> A real attacker would get creative. So we turned Claude Opus 4.6
> into the attacker."

**Run:** `butterfence redteam --count 10 --save`

*Red "AI Red Team Mode" panel appears.*
*Spinner: "Opus 4.6 is thinking like an attacker..."*

**Voiceover (while spinner runs, ~15-20 seconds):**

> "Right now, Opus 4.6 is analyzing this repo's file structure, tech
> stack, and sensitive files. It's generating novel attack scenarios —
> using obfuscation, encoding, variable indirection — things a
> compromised agent would actually try."

*Results table appears — CAUGHT/MISSED column, mostly green.*

> "Look at that. Opus 4.6 generated 10 creative attacks tailored to
> THIS exact repo — and ButterFence caught [X] of them.
> It tried [mention a creative one from the output].
> Claude vs Claude. The model attacks, the harness defends."

*Point out score and catch rate.*

---

## [2:15 - 2:40] REPORTS AND DEPTH

> "Everything generates into reports — Markdown, HTML, JSON, SARIF for
> GitHub Code Scanning, JUnit for CI pipelines."

**Run:** `butterfence report --format html --output report.html`

> "And for CI/CD, one command gates your pipeline:"

**Run:** `butterfence ci --min-score 80`

*Show "CI PASSED" in green.*

> "ButterFence also ships with 7 community rule packs — OWASP, AWS,
> Docker, Node.js, Python, cloud security, and supply chain."

**Run:** `butterfence pack list`

---

## [2:40 - 3:00] THE CLOSE

> "ButterFence. 14 commands. 11 defense categories. 44 built-in
> scenarios. AI-powered red-teaming with Opus 4.6. 299 tests.
> 7 rule packs. 5 export formats. All open source."

**Run:** `butterfence status`

> "As AI agents get more autonomous, trust becomes the bottleneck.
> ButterFence is the safety harness that lets you trust Claude Code
> with your codebase."

> **"Built with Claude Code. Protected by Claude Code."**

*End on the ButterFence banner.*

---

## TIMING SUMMARY

| Section        | Time      | Duration | Key Visual                    |
|----------------|-----------|----------|-------------------------------|
| The Hook       | 0:00-0:20 | 20s      | Problem statement + banner    |
| Initialize     | 0:20-0:40 | 20s      | butterfence init              |
| Live Block     | 0:40-1:05 | 25s      | butterfence scan + findings   |
| Audit          | 1:05-1:30 | 25s      | 44 scenarios, 100/100, A      |
| **AI Red Team**| **1:30-2:15** | **45s** | **butterfence redteam - WOW** |
| Reports/Depth  | 2:15-2:40 | 25s      | HTML report, CI, packs        |
| The Close      | 2:40-3:00 | 20s      | Stats + closing line          |

---

## KEY LINES TO NAIL

1. **"Nobody has solved this for Claude Code. Until now."** (Opening)
2. **"Claude vs Claude. The model attacks, the harness defends."** (Red Team)
3. **"Built with Claude Code. Protected by Claude Code."** (Closing)

---

## PRE-RECORDING CHECKLIST

- [ ] Terminal dark theme, large font, clean background
- [ ] Anthropic API key env var exported
- [ ] demo/vulnerable-repo initialized
- [ ] Test the redteam command once to verify API and timing
- [ ] Clear terminal history
- [ ] Close notifications / Do Not Disturb mode
- [ ] Record at 1920x1080 or higher
- [ ] Practice the full script once (aim for 2:50 to leave buffer)

---

## TIPS

- **Don't rush.** Let the Rich tables render and sit for 2-3 seconds.
  Judges need time to read.
- **The spinner is your friend.** While it spins, explain what's
  happening. It builds tension.
- **If redteam misses some attacks, that's GOOD for the demo.** Say:
  "It found a gap in our rules — that's the whole point."
- **Pre-record, don't live-demo.** Record until you get a clean take.
- **Show your face briefly** at start or end if comfortable.
