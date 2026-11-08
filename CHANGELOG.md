# Changelog

## 2.4.0 — 2026-11-08

- **Section M — Testing and release readiness:** four checks (M-01–M-04) for enforced CI/CD release gates, meaningful unit/integration tests, repeatable e2e on critical journeys (staging/sandbox only), and documented performance budgets with repeatable measurement — with explicit cross-refs to G-02, K-01, K-03, and I-01 so SCA/lockfile/rollback are not mistaken for app test coverage
- Reserved **section L** note on `main` until legal PR merges (draft PR #2, v2.3.0)
- Phase 2 repo probes for workflow/test filenames; Phase 3 severity rubric references M failures; `findings.json` `schemaVersion` → 2.4.0
- Skill item count **~57** (A–K plus M; L reserved externally until merged)

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
