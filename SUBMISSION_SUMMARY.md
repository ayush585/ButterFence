# ButterFence - Submission Summary

**ButterFence** is a Claude Code-native safety harness that red-teams your repository against destructive and secret-leaking AI agent behavior, then auto-generates enforceable hooks to prevent it.

The core innovation is using **Claude Opus 4.6 as the adversary**. The butterfence redteam command scans your repo structure and tech stack, then asks Opus 4.6 to generate creative attack scenarios -- obfuscated commands, encoding tricks, variable indirection -- tailored to YOUR codebase. ButterFence catches them in real-time. When attacks get through, Opus 4.6 analyzes the gaps and generates exact regex patches to close them. One command runs the full attack-patch-verify loop.

Beyond AI red-teaming, ButterFence ships with 44 built-in scenarios across 11 threat categories, 7 community rule packs (OWASP, AWS, Docker), 5 export formats (including SARIF for GitHub Code Scanning), Shannon entropy detection, obfuscation decoding, behavioral chain detection, a live monitoring dashboard, and CI/CD integration.

**Claude attacks. Claude defends. Claude patches.** 299 tests. 35+ modules. All open source.
