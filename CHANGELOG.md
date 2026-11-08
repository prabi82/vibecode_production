# Changelog

## 2.4.0 — 2026-11-08

- **Section M — Testing and release readiness:** four checks (M-01–M-04) for enforced CI/CD release gates, meaningful unit/integration tests, repeatable e2e on critical journeys (staging/sandbox only), and documented performance budgets with repeatable measurement — with explicit cross-refs to G-02, K-01, K-03, and I-01 so SCA/lockfile/rollback are not mistaken for app test coverage
- Phase 2 repo probes for workflow/test filenames; Phase 3 severity rubric references M failures; `findings.json` `schemaVersion` → 2.4.0
- Skill item count **77** (sections A–M)

## 2.3.0 — 2026-11-04

- **Section L — Legal and compliance:** eight code- and site-verifiable checks (L-01–L-08) for privacy-policy accuracy, AI/subprocessor disclosure, real deletion, truthful marketing, subscription cancel parity, trial billing notice, and safe consumer AI chat — with typical-exposure framing (not legal advice) and a recurring policy review reminder
- Phase 2 adds a polite `/privacy` probe; Phase 3 severity rubric references L failures; `findings.json` `schemaVersion` → 2.3.0

## 2.2.1 — 2026-10-08

- **F-01** strengthened: rate limits on public ID/search reads (cache-penetration / DB miss floods), per-IP and per-user keys, short TTL negative caching when a cache layer exists; Bloom filters noted as optional only
- Phase 3 **Medium** severity: unlimited public lookups without limits (F-01)

## 2.2.0 — 2026-10-03

Eight additional vibe-coded production checks:

- **A-07** — RLS own-row updates cannot mutate privileged columns (`role`, `plan`, `credits`, `is_admin`, etc.); Pass requires second-account verification
- **A-08** — Separate public uploads from private backups/config; signed URLs with expiry; access logging
- **B-06** — No third-party scripts on login, checkout, or admin (CSP elsewhere does not satisfy)
- **C-06** — Transactional email: user-controlled fields rendered as text, not raw HTML
- **D-12** — Per-handler auth; middleware matcher gaps (Next.js API routes, path variants)
- **D-13** — PKCE required for public/mobile OAuth clients (not optional with `state` alone)
- **E-06** — Server Components / APIs select only fields the UI needs (no password hash leakage)
- **J-04** — Agents use scoped short-lived credentials, human approval for prod side effects, per-session audit logs
- Severity rubric updated for the new failure modes

## 2.1.0 — 2026-10-03

Google Sign-In / OAuth production checks in section D (common vibe-coded mistakes):

- **D-08** — Google OAuth redirect URI allowlist (Console + server-side validation)
- **D-09** — OAuth `state` (and PKCE where applicable) on authorization callback
- **D-10** — Minimum Google OAuth scopes for sign-in-only flows
- **D-11** — Server-side Google ID token verification (`iss`, `aud`, `exp`, signature, `email_verified`)
- **D-06** narrowed to app-issued JWTs; hunt strings extended for Google OAuth
- Severity rubric: unverified ID token / client-trusted identity → Critical; missing `state` or open redirect URI handling → High

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
