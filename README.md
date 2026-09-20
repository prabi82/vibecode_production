# vibecode-production

A Cursor / Claude skill that audits a vibe-coded or AI-generated app before (or after) production deploy.

The original 19-item checklist (RLS, CORS, SQLi, email verify, tokens, `.env`, validation, admin routes, debug, secrets, review pass, rate limits, uploads, logs, password hashing, webhooks, permissions, XSS, dependencies) is preserved and expanded to a stack-aware production-readiness pass: transport headers, CSRF, sessions, JWT/OAuth, SSRF, supply-chain slopsquatting, LLM keys, host exposure, backups, and leftover `TODO: add auth` / mock auth.

## Install

Clone into your personal skills directories:

```bash
git clone https://github.com/prabi82/vibecode_production.git ~/.cursor/skills/vibecode-production
git clone https://github.com/prabi82/vibecode_production.git ~/.claude/skills/vibecode-production
```

On Windows (PowerShell):

```powershell
git clone https://github.com/prabi82/vibecode_production.git "$env:USERPROFILE\.cursor\skills\vibecode-production"
git clone https://github.com/prabi82/vibecode_production.git "$env:USERPROFILE\.claude\skills\vibecode-production"
```

The agent-facing file is [`SKILL.md`](SKILL.md). Cursor and Claude pick it up from those skill folders.

## Usage

In a project you are about to ship, paste:

```
Hey Claude, I don't want my vibe coded website to get hacked, so I need you to review this project for production security. Please make no mistakes.

Audit the codebase (and the live deploy if a URL is provided) against every item in the vibecode-production skill. For each item: status (Pass/Fail/N/A), where it fails, severity (critical/high/medium/low), and the exact fix. Do not mark Pass without pointing at the code or config that proves it.
```

Or ask the agent to follow `/vibecode-production` / the `vibecode-production` skill.

The agent writes `VIBECODE-PRODUCTION.md` (and optional `findings.json`) with a scorecard and a **GO / CONDITIONAL GO / NO-GO** verdict.

## What it is not

- Not a deep authorized pentest — use [fable-pentest](https://github.com/prabi82/fable-pentest).
- Not a full OWASP practitioner audit with CVSS/ASVS reports — use [fable-securityaudit](https://github.com/prabi82/fable-securityaudit).

## Credit

v1.0.0 started from the Josh Hoeg-style 19-item vibe-coded security checklist. v2.0.0 adds the missing production-readiness domains listed in [`CHANGELOG.md`](CHANGELOG.md).
