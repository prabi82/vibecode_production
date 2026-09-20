# Changelog

## 2.0.0 — 2026-09-20

Expanded the 19-item vibe-coded security checklist into a stack-aware production-readiness skill (~50 items).

- Frontmatter: `name: vibecode-production`, version, compatibility, sibling-skill routing
- Phase 0 stack detection (Next.js, Supabase, Firebase, Laravel, Django/Flask, Rails, Workers, Vercel/Netlify)
- Original 19 checks preserved and tagged `(orig N)`
- New domains: transport/headers/CSRF, session/JWT/OAuth, mass assignment, open redirects, SSRF/GraphQL, storage/service-role keys, secrets scanning, webhook replay, payments/idempotency, lockfile and slopsquatting, CDN SRI, origin/admin/SSH exposure, backups/PII/env split, LLM keys and prompt injection, audit/alerting/rollback, vibe-coding leftovers
- Phase 2 polite live-URL and repo probes
- Phase 3 severity rubric and GO / CONDITIONAL GO / NO-GO verdict
- Report template `VIBECODE-PRODUCTION.md` plus optional `findings.json`

## 1.0.0

Original 19-item checklist: RLS, CORS, parameterized SQL, email verify, tokens out of localStorage, hide `.env`, validate inputs, protect admin routes, disable debug, server-side secrets, security review pass, rate limits, file uploads, redact logs, hash passwords, webhook signatures, server-side permissions, XSS, update dependencies.
