---
name: vibecode-production
description: >-
  Use when reviewing a vibe-coded or AI-generated app before or after production
  deploy: RLS, secrets, auth, XSS, CSRF, headers, rate limits, uploads, webhooks,
  supply chain, LLM keys, host exposure, and leftover mock/TODO auth. Don't use
  for a deep authorized pentest (use fable-pentest) or a full OWASP practitioner
  audit with CVSS/ASVS reports (use fable-securityaudit).
version: 2.0.0
compatibility: cursor, claude
---

# Vibe-coded production readiness

Audit an AI/vibe-coded app that is going to production or is already live. Run against the real codebase and, when a URL is provided, the live deploy. Report every item as Pass / Fail / N/A with evidence and a concrete fix. Never mark Pass without a file:line, config key, or response header.

## When to use / when not to

**Use** when the user asks to ship, harden, "make it production ready", or "don't get hacked" on a vibe-coded / Cursor / Claude / Copilot / Lovable / Bolt / v0 app.

**Don't use** for exploit development, full nmap/host sweeps without written authorization, or a multi-day OWASP audit. Route those to `fable-pentest` / `fable-securityaudit`.

## Opening prompt (paste into the coding agent)

```
Hey Claude, I don't want my vibe coded website to get hacked, so I need you to review this project for production security. Please make no mistakes.

Audit the codebase (and the live deploy if a URL is provided) against every item in the vibecode-production skill. For each item: status (Pass/Fail/N/A), where it fails, severity (critical/high/medium/low), and the exact fix. Do not mark Pass without pointing at the code or config that proves it.
```

## Phase 0 — Stack detection

Detect the stack first. Mark items N/A only when the concern cannot exist on that stack, and say why.

| Signals | Stack | Typical N/A |
|---------|-------|-------------|
| `next`, `src/app`, `middleware.ts` | Next.js / Node | — |
| `supabase`, `service_role` | Supabase / Postgres | — |
| `firebase`, `firestore.rules` | Firebase | SQL/RLS → use Security Rules |
| `artisan`, `composer.json`, `.env` | Laravel / PHP | — |
| `manage.py`, `settings.py`, `Flask` | Django / Flask | — |
| `Gemfile`, `config/routes.rb` | Rails | — |
| `wrangler.toml`, `workers` | Cloudflare Workers | classic SSH/host items if fully on Workers |
| `vercel.json`, `netlify.toml` | Vercel / Netlify | origin/SSH if no VPS |

Hunt leftovers everywhere: `TODO: add auth`, `allowAll`, `SKIP_AUTH`, `dangerouslySetInnerHTML`, `NEXT_PUBLIC_`, `service_role`, `queryRawUnsafe`.

---

## Phase 1 — Checklist

Work every item. Do not skip Fail because the app “works.” Original 19 checks are marked `(orig N)`.

### A — Access control and data isolation

| ID | Check | How to verify |
|----|-------|---------------|
| A-01 | **Enable RLS** `(orig 1)` | Every Postgres/Supabase/Firebase table has RLS or equivalent; anon/public cannot read/write other users’ rows. |
| A-02 | **Protect admin routes** `(orig 8)` | Admin/debug/internal routes check authz on the server; hidden UI is not enough. |
| A-03 | **Server-side permissions / IDOR** `(orig 17)` | Every sensitive action re-checks ownership/role on the server (object IDs in URL/body). |
| A-04 | **Mass assignment** | Create/update DTOs allowlist fields; clients cannot set `role`, `isAdmin`, `price`, `verified`. |
| A-05 | **Open redirects** | Redirect targets are relative or allowlisted; no `?next=https://evil`. |
| A-06 | **Storage and privileged keys** | Buckets not world-public; signed URLs expire; Supabase `service_role` / Firebase Admin SDK never in the client. |

Hunt: `service_role`, `isAdmin`, `role:`, `redirect(`, `createSignedUrl`, `allowAll`.

### B — Transport, CORS, headers, CSRF

| ID | Check | How to verify |
|----|-------|---------------|
| B-01 | **HTTPS and HSTS** | HTTP redirects to HTTPS; `Strict-Transport-Security` with a long `max-age` in production. |
| B-02 | **Tighten CORS** `(orig 2)` | Origins are an explicit allowlist (not `*`) in production; credentials only where required. |
| B-03 | **Security headers + CSP** | `Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`. Tighten `unsafe-inline`/`unsafe-eval` if present. |
| B-04 | **Cookie flags** | Session cookies: `Secure`, `HttpOnly`, `SameSite=Lax` or `Strict`. |
| B-05 | **CSRF** | Cookie sessions have CSRF tokens or SameSite+origin checks; state-changing APIs reject cross-site posts. |

Hunt: `Access-Control-Allow-Origin`, `cors(`, `sameSite`, `csrf`.

### C — Injection, XSS, uploads, SSRF

| ID | Check | How to verify |
|----|-------|---------------|
| C-01 | **Parameterized queries** `(orig 3)` | No string-built SQL/NoSQL from user input; ORM bindings / `$1` / `?` everywhere. |
| C-02 | **Validate form inputs** `(orig 7)` | Server-side validation (length, type, allowlist) on every write; client-only checks do not count. |
| C-03 | **Block XSS** `(orig 18)` | Output encoding; no unsanitized user HTML; frameworks used safely; CSP as defense in depth. |
| C-04 | **Validate file uploads** `(orig 13)` | Type, size, and content checks; safe storage path; no executable uploads to public buckets. |
| C-05 | **SSRF and GraphQL** | User-supplied URLs are allowlisted; no internal metadata hops. GraphQL: introspection off in prod; depth/cost limits. |

Hunt: `queryRawUnsafe`, `dangerouslySetInnerHTML`, `innerHTML`, `eval(`, `fetch(req.url`, `graphql`.

### D — Auth, sessions, tokens

| ID | Check | How to verify |
|----|-------|---------------|
| D-01 | **Verify email** `(orig 4)` | Signup/login requires verified email (or documented MFA) before privileged actions. |
| D-02 | **Tokens out of localStorage** `(orig 5)` | Access/session tokens not in `localStorage`/`sessionStorage` if avoidable; prefer httpOnly Secure cookies. |
| D-03 | **Hash passwords** `(orig 15)` | Modern hash (argon2/bcrypt/scrypt); never plain text or reversible encryption. |
| D-04 | **Session hygiene** | Idle/absolute expiry; rotate session ID on login; logout invalidates server-side. |
| D-05 | **Lockout, enumeration, resets** | Auth endpoints lock or slow down after failures. Errors do not reveal whether an email exists. Reset tokens are random, single-use, short-lived, stored hashed. |
| D-06 | **JWT and OAuth** | JWT: explicit `alg`, expiry, issuer/audience, strong secret. OAuth: redirect URI allowlist; no `redirect_uri` open redirect. |
| D-07 | **Password policy and admin MFA** | Minimum length + breached-password check where feasible. MFA required for admin/owner roles. |

Hunt: `localStorage.setItem`, `jwt.sign`, `algorithm: 'none'`, `bcrypt`, `password.reset`.

### E — Secrets, debug, logs

| ID | Check | How to verify |
|----|-------|---------------|
| E-01 | **Hide .env from Git** `(orig 6)` | `.env`, `.env.*`, and secret files are gitignored; none in commit history; rotate any that were committed. |
| E-02 | **Server-side API secrets** `(orig 10)` | Keys exist only on server/edge; no `NEXT_PUBLIC_*` / `VITE_*` / `EXPO_PUBLIC_*` secrets; not in frontend bundles. |
| E-03 | **Sensitive data out of logs** `(orig 14)` | Passwords, tokens, PII, and full payment data are not logged; redact before logging. |
| E-04 | **Disable production debugging** `(orig 9)` | No stack traces, debug panels, source maps, or verbose errors to clients in production. |
| E-05 | **Secrets scan** | Run gitleaks/trufflehog (or equivalent) on the repo; fix and rotate hits. |

Hunt: `process.env.NEXT_PUBLIC_`, `console.log(.*password|token|secret`, `APP_DEBUG`, `sourceMap`.

### F — Rate limits, webhooks, payments

| ID | Check | How to verify |
|----|-------|---------------|
| F-01 | **Rate limit requests** `(orig 12)` | Auth, signup, password reset, uploads, and public APIs have limits / WAF / abuse protection. |
| F-02 | **Verify webhook signatures** `(orig 16)` | Inbound webhooks check provider signatures and timestamps before trusting the body. |
| F-03 | **Webhook replay** | Reject old timestamps; persist event IDs so the same event is not applied twice. |
| F-04 | **Server-side prices** | Amounts, SKUs, and discounts are computed on the server; client-sent prices are ignored. |
| F-05 | **Idempotency and auth cache** | Payment/order POSTs accept idempotency keys. Authenticated HTML/JSON is `Cache-Control: private, no-store`. |

Hunt: `webhook`, `stripe.webhooks`, `req.body.price`, `idempotency`.

### G — Supply chain

| ID | Check | How to verify |
|----|-------|---------------|
| G-01 | **Update dependencies** `(orig 19)` | No known critical CVEs in the lockfile; `npm audit` / `composer audit` / `pip-audit` / `osv-scanner` clean or documented waivers. |
| G-02 | **Lockfile pinned** | `package-lock.json` / `pnpm-lock.yaml` / `composer.lock` / `poetry.lock` committed; CI installs from the lockfile. |
| G-03 | **Hallucinated / slopsquatted packages** | Every dependency exists on the real registry and is the intended package; drop typosquats and AI-invented names. |
| G-04 | **CDN scripts and SRI** | Third-party `<script src>` uses `integrity` + `crossorigin`, or is bundled; no mystery CDNs. |

Hunt: lockfile presence, `cdn.jsdelivr`, `unpkg`, unusual package names in `package.json`.

### H — Infrastructure and host

| ID | Check | How to verify |
|----|-------|---------------|
| H-01 | **Origin not world-open** | If a CDN/WAF is in front, origin 80/443 is allowlisted to that CDN (or equivalent). Direct IP should not serve the app to the world. |
| H-02 | **Admin panels off the WAN** | Plesk, cPanel, phpMyAdmin, pgAdmin, Cognos, `/server-status` not publicly reachable; use VPN, SSH tunnel, or Cloudflare Access. |
| H-03 | **SSH and default credentials** | SSH is key-only; no default `admin/admin` on panels, DBs, or the app. |
| H-04 | **`.git` / backups not served** | `/.git/HEAD`, `.env`, `*.sql`, `*.bak`, `wp-config.php~` return 403/404. |
| H-05 | **Listing, maps, DB exposure** | Directory listing off; production source maps not public. DB port not on 0.0.0.0/WAN; app DB user is least-privilege; TLS to DB when remote. |

N/A when the app is fully on a managed host with no VPS (document why).

### I — Data, privacy, environments

| ID | Check | How to verify |
|----|-------|---------------|
| I-01 | **Backups and encryption** | Automated backups exist; restore has been tested or is scheduled. Disk/DB encryption at rest is on for hosted data stores. |
| I-02 | **PII minimisation and rights** | Collect only needed PII. Documented export/delete path if you store personal data. |
| I-03 | **Prod / staging split** | Separate projects/DBs/keys. No shared prod credentials in staging. |
| I-04 | **No demo or test leftovers in prod** | No seed users with known passwords, test Stripe keys, or `ngrok` callbacks in production config. |

### J — AI / LLM endpoints

Mark N/A if the app has no model/API calls.

| ID | Check | How to verify |
|----|-------|---------------|
| J-01 | **Keys and spend caps** | LLM/provider keys only on the server; per-user and global rate/spend caps. |
| J-02 | **Prompt injection / untrusted output** | User and retrieved content is treated as data, not instructions. Model HTML/JSON is sanitized before render or tool use. |
| J-03 | **Tool scope** | Agent tools cannot email everyone, drop tables, or call arbitrary URLs; confirmations for side effects. |

### K — Ops and vibe-coding leftovers

| ID | Check | How to verify |
|----|-------|---------------|
| K-01 | **Security review pass** `(orig 11)` | Automated review (SCA/SAST, e.g. `osv-scanner`, semgrep, or vendor security-review) run; critical/high fixed or waived in writing. |
| K-02 | **Audit log and alerting** | Auth failures, admin actions, and payments are logged (no secrets). Error tracker + uptime with PII scrub; someone is paged on 5xx/auth spikes. |
| K-03 | **Rollback plan** | Documented way to revert a deploy (previous image, host rollback, or `git revert` + CI). |
| K-04 | **Vibe leftovers** | No `// TODO: add auth`, commented-out guards, `mockAuth` / `allowAll` / `bypassAuth`, hardcoded passwords, placeholder emails, or debug routes left enabled. |

Hunt: `TODO: add auth`, `FIXME`, `bypassAuth`, `SKIP_AUTH`, `allowAll`, `password123`, `admin@example.com`, `console.log`.

---

## Phase 2 — Live URL and repo probes

Authorization: polite `HEAD`/`GET` of the app URL, well-known paths, and TLS/headers is in-scope when the user asked for a production review of their own deploy. Do not port-sweep, exploit, or brute-force.

```bash
# Headers / HTTPS
curl -sI https://APP
curl -sI http://APP

# Sensitive paths (expect 403/404, not 200 with content)
curl -sI https://APP/.env
curl -sI https://APP/.git/HEAD
curl -sI https://APP/admin

# Deps + secrets (repo)
npx osv-scanner -r . || npm audit --production
composer audit || pip-audit || true
gitleaks detect --no-git -v || true
```

Record: status code, notable headers (`strict-transport-security`, `content-security-policy`, `access-control-allow-origin`, `set-cookie`, `cache-control`), and whether source maps or verbose errors appear.

---

## Phase 3 — Severity and verdict

| Severity | Use when |
|----------|----------|
| Critical | Unauth RCE, auth bypass, world-readable secrets/PII, public admin, SQLi/command injection, service-role in the client |
| High | IDOR, stored XSS, missing RLS on user data, webhook without signature, origin bypass of CDN, password in git, no rate limit on auth |
| Medium | Missing headers/HSTS, CSRF on cookie session, verbose errors, weak CSP, lockfile missing, backups untested |
| Low | Info leaks, missing MFA on admin, SRI gaps, incomplete audit logs |

**Verdict**

- **NO-GO** — any open Critical, or two or more open High, or production secrets still in git/client.
- **CONDITIONAL GO** — no Critical; at most one High with a dated fix plan; Medium/Low listed.
- **GO** — no open Critical/High; Medium/Low accepted or scheduled.

---

## How to report

Write `VIBECODE-PRODUCTION.md` (and optional `findings.json`) at the repo root or `docs/security/`.

Scorecard:

| ID | Check | Status | Severity | Evidence / fix |
|----|-------|--------|----------|----------------|
| A-01 | Enable RLS | Pass/Fail/N/A | … | `path:line` or header |

Then:

1. **Verdict** — GO / CONDITIONAL GO / NO-GO (one sentence).
2. **Must-fix before traffic** — every Fail at critical/high.
3. **Optional hardening** — medium/low and defense in depth.

Optional `findings.json` envelope:

```json
{
  "schemaVersion": "2.0.0",
  "skill": "vibecode-production",
  "generatedAt": "2026-09-20T00:00:00.000Z",
  "verdict": "NO-GO",
  "findings": [
    {
      "id": "A-01",
      "severity": "High",
      "evidence": "supabase/migrations — RLS disabled on profiles",
      "status": "open"
    }
  ]
}
```

`severity`: `Critical` | `High` | `Medium` | `Low` | `Info`.  
`status`: `open` | `fixed` | `accepted` | `not_tested` | `n/a`.

---

## Rules

- Prefer reading real config and routes over guessing.
- If a stack does not use SQL/RLS/webhooks/LLM/a VPS, mark N/A and say why.
- Never invent Pass. If unsure, Fail or N/A with what to verify next.
- After fixes, re-run only the failed items unless the user asks for a full recheck.
- Do not mark Pass without file:line, config, or a live header/status code.
- Do not write exploit PoCs. Describe the fix and the missing control.
- Active scans beyond polite HTTP/TLS require written authorization in the report Scope.
