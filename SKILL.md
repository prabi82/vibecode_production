---
name: vibecode-production
description: >-
  Use when reviewing a vibe-coded or AI-generated app before or after production
  deploy: RLS, secrets, auth, XSS, CSRF, headers, rate limits, uploads, webhooks,
  supply chain, LLM keys, host exposure, legal/compliance hygiene, leftover mock/TODO
  auth, and release gates (CI/CD, unit/integration/e2e tests, performance budgets).
  Don't use for a deep authorized pentest (use fable-pentest) or a full OWASP
  practitioner audit with CVSS/ASVS reports (use fable-securityaudit).
version: 2.5.0
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
| A-01 | **Enable RLS** `(orig 1)` | Every Postgres/Supabase/Firebase table with user data has RLS or equivalent; anon/public cannot read/write other users’ rows. **Supabase:** the browser **anon** / **publishable** key is **expected** — not a Fail by itself (see **E-02**). **Fail:** RLS disabled, permissive `USING (true)` policies, or **service_role** in client code dumping cross-user data. **Pass:** RLS on every sensitive table; policies restrict rows to the owning user/tenant with evidence (`path:line` or migration). **Fix:** Enable RLS; tighten policies; move privileged reads to the server. |
| A-02 | **Protect admin routes** `(orig 8)` | Admin/debug/internal routes check authz on the server; hidden UI is not enough. |
| A-03 | **Server-side permissions / IDOR** `(orig 17)` | Every sensitive action re-checks ownership/role on the server (object IDs in URL/body). |
| A-04 | **Mass assignment** | Create/update DTOs allowlist fields; clients cannot set `role`, `isAdmin`, `price`, `verified`. |
| A-05 | **Open redirects** | Redirect targets are relative or allowlisted; no `?next=https://evil`. |
| A-06 | **Storage and privileged keys** | Buckets not world-public; signed URLs expire; Supabase `service_role` / Firebase Admin SDK never in the client. |
| A-07 | **RLS: own-row is not own-everything** | N/A if no Postgres/Supabase/Firebase RLS (use equivalent column rules on other stacks). Policies that let users `UPDATE` their own profile/row must **not** allow writing privileged columns: `role`, `plan`, `tier`, `credits`, `balance`, `rate_limit`, `is_admin`, `isAdmin`, `verified`, `stripe_customer_id`, or similar. **Pass:** Policy `WITH CHECK` / column grants / triggers block privilege bumps; evidence includes what a **second normal test account** can still change on its own row (e.g. display name only)—not just reading the policy text. **Fail:** `USING (auth.uid() = user_id)` on `UPDATE` without column restrictions, or ORM `update()` accepts the full row from the client. **Fix:** Split policies or use `WITH CHECK` on allowed columns; server-only updates for billing/role; mirror with app-layer allowlists (A-04). Default severity if fail: **High** (self-serve privilege escalation). |
| A-08 | **Public vs private object storage** | N/A if the app has no file/object storage. Public buckets (avatars, marketing assets) must **not** also hold DB dumps, backups, `.env`, exports, or config. Private objects use **short-lived signed URLs** (or authenticated proxy download), not long-lived public URLs. Enable provider access logging on private buckets. Obscure bucket names are **not** access control. **Pass:** Separate buckets/prefixes with IAM; private data never `public-read`; logging on in console/IaC (`path:line` or config). **Fail:** One public bucket for uploads and backups; signed URLs without expiry; security through random bucket name. **Fix:** Split public/private storage; tighten ACLs; expire signed URLs; turn on access logs. Default severity if fail: **Critical** when backups/config are world-readable; **High** otherwise. |

Hunt: `service_role`, `isAdmin`, `role:`, `redirect(`, `createSignedUrl`, `allowAll`, `WITH CHECK`, `auth.uid()`, `is_admin`, `credits`, `public-read`, `getPublicUrl`.

### B — Transport, CORS, headers, CSRF

| ID | Check | How to verify |
|----|-------|---------------|
| B-01 | **HTTPS and HSTS** | HTTP redirects to HTTPS; `Strict-Transport-Security` with a long `max-age` in production. |
| B-02 | **Tighten CORS** `(orig 2)` | Origins are an explicit allowlist (not `*`) in production; credentials only where required. |
| B-03 | **Security headers + CSP** | `Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`. Tighten `unsafe-inline`/`unsafe-eval` if present. |
| B-04 | **Cookie flags** | Session cookies: `Secure`, `HttpOnly`, `SameSite=Lax` or `Strict`. |
| B-05 | **CSRF** | Cookie sessions have CSRF tokens or SameSite+origin checks; state-changing APIs reject cross-site posts. |
| B-06 | **No third-party scripts on sensitive pages** | N/A if login, checkout, and admin are not web pages (e.g. native-only). Login, signup, password reset, checkout/payment, and admin surfaces must **not** load third-party `<script>` tags (chat widgets, analytics, A/B snippets, tag managers) that can read form fields, cookies, or session-bearing requests. A strict CSP on other routes does **not** Pass this item if those pages still embed vendors. **Pass:** Sensitive routes use a minimal layout with no external scripts (or first-party-only bundle); evidence from layout/`page` files and live HTML. **Fail:** Intercom/Crisp/GA/GTM/segment snippets on `/login`, `/checkout`, `/admin`, etc. **Fix:** Remove vendor scripts from auth/payment/admin layouts; load analytics only on marketing pages or after auth via a separate origin/subdomain policy. Default severity if fail: **High** (credential and payment data exposure to third parties). |

Hunt: `Access-Control-Allow-Origin`, `cors(`, `sameSite`, `csrf`, `googletagmanager`, `gtag`, `intercom`, `crisp`, `segment.com`, `hotjar`, `clarity.ms`.

### C — Injection, XSS, uploads, SSRF

| ID | Check | How to verify |
|----|-------|---------------|
| C-01 | **Parameterized queries** `(orig 3)` | No string-built SQL/NoSQL from user input; ORM bindings / `$1` / `?` everywhere. |
| C-02 | **Validate form inputs** `(orig 7)` | Server-side validation (length, type, allowlist) on every write; client-only checks do not count. |
| C-03 | **Block XSS** `(orig 18)` | Output encoding; no unsanitized user HTML; frameworks used safely; CSP as defense in depth. |
| C-04 | **Validate file uploads** `(orig 13)` | Type, size, and content checks; safe storage path; no executable uploads to public buckets. |
| C-05 | **SSRF and GraphQL** | User-supplied URLs are allowlisted; no internal metadata hops. GraphQL: introspection off in prod; depth/cost limits. |
| C-06 | **Transactional email: user fields as text** | N/A if the app sends no transactional email (Resend, SendGrid, Postmark, Clerk emails, etc.). Templates must render user-controlled fields (name, company, message preview) as **plain text** or escaped text—not raw HTML—so a display name cannot become a phishing link sent from your domain. **Pass:** Template uses text bodies, provider “plain” mode, or explicit escaping for all user-derived placeholders (`path:line`). **Fail:** `html:` templates with unescaped `{{user.name}}`, or React-email components that inject user HTML. **Fix:** Plain-text emails for auth flows; escape HTML entities; separate marketing HTML with no user-controlled markup. Default severity if fail: **High** (domain-trusted phishing). |

Hunt: `queryRawUnsafe`, `dangerouslySetInnerHTML`, `innerHTML`, `eval(`, `fetch(req.url`, `graphql`, `resend`, `@react-email`, `html:`, `sendgrid`, `postmark`.

### D — Auth, sessions, tokens

| ID | Check | How to verify |
|----|-------|---------------|
| D-01 | **Verify email** `(orig 4)` | Signup/login requires verified email (or documented MFA) before privileged actions. |
| D-02 | **Tokens out of localStorage** `(orig 5)` | Access/session tokens not in `localStorage`/`sessionStorage` if avoidable; prefer httpOnly Secure cookies. |
| D-03 | **Hash passwords** `(orig 15)` | Modern hash (argon2/bcrypt/scrypt); never plain text or reversible encryption. |
| D-04 | **Session hygiene** | Idle/absolute expiry; rotate session ID on login; logout invalidates server-side. |
| D-05 | **Lockout, enumeration, resets** | Auth endpoints lock or slow down after failures. Errors do not reveal whether an email exists. Reset tokens are random, single-use, short-lived, stored hashed. |
| D-06 | **JWT (app-issued)** | JWT: explicit `alg`, expiry, issuer/audience, strong secret; reject `none` / confused algorithms. N/A if the app does not issue JWTs. |
| D-07 | **Password policy and admin MFA** | Minimum length + breached-password check where feasible. MFA required for admin/owner roles. |
| D-08 | **Google OAuth redirect URIs** | N/A if the app does not use Google Sign-In / Google OAuth. In Google Cloud Console, OAuth client redirect URIs are an exact allowlist for known app origins only (no `*`, no open patterns, no stray `http://localhost` on production clients unless documented dev-only). App code must not honor a client-supplied `redirect_uri` without validating it against that same allowlist on the server. **Pass:** Console URIs and server callback validation match production/staging hosts with evidence (`path:line` or config). **Fail:** Wildcard/extra URIs, or redirect target taken from the query/body without allowlist. **Fix:** Remove unused URIs in Console; validate `redirect_uri` server-side against a fixed list; use framework defaults that pin the callback URL. |
| D-09 | **Google OAuth `state` (CSRF)** | N/A if no Google OAuth. Authorization URL includes a cryptographically random `state` stored server-side (session or signed cookie) before redirecting to Google; callback handler compares incoming `state` and aborts before code exchange or session creation when missing or mismatched. `state` does **not** replace PKCE on public clients—see **D-13**. **Pass:** `state` generated, bound to the user agent, and verified on callback (`path:line`). **Fail:** No `state`, static/predictable `state`, or callback never validates it. **Fix:** Generate `state` per login attempt; verify on callback; reject the flow on mismatch. Default severity if fail: **High**. |
| D-10 | **Google OAuth scopes** | N/A if no Google OAuth. Request the minimum scopes: typically `openid` plus `email` / `profile` (or equivalent userinfo scopes) for sign-in only. **Pass:** Authorize URL / client config lists only needed scopes with evidence. **Fail:** Broad or sensitive scopes (Gmail, Drive, Calendar, `https://www.googleapis.com/auth/...` admin scopes) without a documented product feature that needs them. **Fix:** Drop unused scopes in code and in the Google Cloud OAuth consent screen; re-consent users if you had over-scoped before. |
| D-11 | **Verify Google ID token server-side** | N/A if no Google OAuth. After sign-in, identity comes from a **server-verified** Google ID token (or token endpoint response verified the same way)—not from trusting `email`, `sub`, or raw token fields posted from the browser. Verify signature (Google JWKS), `iss` is `accounts.google.com` or `https://accounts.google.com`, `aud` matches your OAuth client ID, `exp` (and `nbf` if present) are valid, and `email_verified` is true when email is used to create or match accounts. **Pass:** Server path calls Google’s verifier library or equivalent JWKS validation before creating a session (`path:line`). **Fail:** Login API trusts client JSON, decodes JWT without signature check, skips `aud`/`iss`/`exp`, or ignores `email_verified`. **Fix:** Verify the ID token on the server; bind sessions only to verified claims; never use client-supplied email/`sub` as proof of identity. |
| D-12 | **Auth in every sensitive handler** | N/A if the app has no HTTP API or server routes. Framework middleware (e.g. Next.js `middleware.ts` matchers) is **not** sufficient alone: every sensitive route handler, Server Action, and API route re-validates the session/role before side effects. Check matcher gaps—`/api/*`, route groups, `_next` misconfig, alternate path encodings, and handlers added without updating the matcher. **Pass:** Each protected `route.ts` / action calls shared `requireAuth`/`requireAdmin` (or equivalent) at the top; spot-check unlisted paths. **Fail:** Protection only in middleware or layout; new API route with no session check. **Fix:** Central guard helper; call it in every handler; align matcher with actual routes or drop matcher-only reliance. Default severity if fail: **High** (auth bypass). |
| D-13 | **OAuth PKCE (public / mobile clients)** | N/A if OAuth runs only on a confidential server-side client with no browser/mobile code exchange. Public SPAs, mobile apps, and native OAuth clients **must** use PKCE (`code_challenge` / `code_verifier`, S256) on the authorization and token steps. `state` alone does not stop authorization-code interception on a shared network. **Pass:** Authorize URL sends `code_challenge`; token exchange sends `code_verifier`; client is registered as public/native where required (`path:line`). **Fail:** Implicit flow, public client exchanging code without PKCE, or PKCE documented only as optional. **Fix:** Enable PKCE in the OAuth library; reject token requests without valid verifier. Default severity if fail: **High**. |

Hunt: `localStorage.setItem`, `jwt.sign`, `algorithm: 'none'`, `bcrypt`, `password.reset`, `accounts.google.com`, `googleusercontent`, `client_id`, `redirect_uri`, `state`, `scope=`, `id_token`, `verifyIdToken`, `OAuth2Client`, `GoogleAuth`, `openid`, `passport-google`, `next-auth/providers/google`, `@react-oauth/google`, `gsi/client`, `code_challenge`, `code_verifier`, `middleware.ts`, `matcher`, `requireAuth`, `getServerSession`.

### E — Secrets, debug, logs

| ID | Check | How to verify |
|----|-------|---------------|
| E-01 | **Hide .env from Git** `(orig 6)` | `.env`, `.env.*`, and secret files are gitignored; none in commit history; rotate any that were committed. |
| E-02 | **Server-side API secrets** `(orig 10)` | Privileged keys (`service_role`, provider **secret** keys, signing keys, admin tokens) exist only on server/edge — not in frontend bundles or committed `NEXT_PUBLIC_*` / `VITE_*` / `EXPO_PUBLIC_*` **secrets**. **Supabase:** the **anon** / **publishable** key in client code is **expected** and is **not** a finding by itself; **Fail** is `service_role` / `SUPABASE_SERVICE_ROLE_KEY` (or equivalent) shipped to the browser, or missing RLS on tables that key can reach (**A-01**). **Pass:** Only public/anon keys client-side; privileged calls via server routes (`path:line`). **Fail:** Service role or payment/LLM secret in bundle. **Fix:** Strip from client; env on server only. Default severity if fail: **Critical** for `service_role` or payment secrets in client. |
| E-03 | **Sensitive data out of logs** `(orig 14)` | Passwords, tokens, PII, and full payment data are not logged; redact before logging. |
| E-04 | **Disable production debugging** `(orig 9)` | No stack traces, debug panels, source maps, or verbose errors to clients in production. |
| E-05 | **Secrets scan** | Run gitleaks/trufflehog (or equivalent) on the repo; fix and rotate hits. |
| E-06 | **Minimize server payloads (RSC / API)** | Server Components, loaders, and JSON APIs must not return columns or fields the UI does not need—especially `password_hash`, `hashed_password`, API keys, refresh tokens, internal billing IDs, or `service_role` material. **Pass:** Queries use explicit `select` / DTO projection; sample authenticated API/RSC responses show only rendered fields (`path:line` + response shape). **Fail:** `SELECT *`, ORM `user` entity returned wholesale, or GraphQL list fields exposing secrets. **Fix:** Project to DTOs at the boundary; strip sensitive columns in serializers; never pass full DB rows to the client. Default severity if fail: **Critical** when secrets/password hashes leak; **High** for other sensitive columns. |

Hunt: `process.env.NEXT_PUBLIC_`, `console.log(.*password|token|secret`, `APP_DEBUG`, `sourceMap`, `select('*')`, `password_hash`, `hashedPassword`, `findUnique` without `select`.

### F — Rate limits, webhooks, payments

| ID | Check | How to verify |
|----|-------|---------------|
| F-01 | **Rate limit requests** `(orig 12)` | N/A only when the app has no HTTP APIs and no user-facing reads (static site with no backend). Rate limits and abuse controls cover **auth** (login, signup, password reset), **uploads**, **public read endpoints**, and **outbound email/SMS senders**—not just generic “public APIs.” Include lookup-by-ID routes (e.g. `/api/items/:id`, `/users/:uuid`) and **search** (`?q=`, `/search`, GraphQL list queries) that hit the database. **Email/SMS (N/A if the app never sends mail or texts):** Any invite, share-link, contact, resend-verification, or notify-other-user endpoint needs **per-user** and **per-IP** send quotas plus **per-recipient cooldown** so one form cannot blast thousands of messages and burn domain reputation. **Pass:** Limits are enforced **per IP** and **per authenticated user** (when signed in) on HTTP routes and send handlers; evidence at middleware/WAF/edge or handler (`path:line` or config). **Fail:** Only auth routes limited; ID/search endpoints unlimited; unlimited invite/contact sends. **Fix:** Add edge or app rate limits on hot read/search routes and mail/SMS paths; key by IP + user id + recipient. **Cache (N/A if no Redis/Upstash/KV/CDN read cache):** Misses for unknown IDs should be cached briefly as “not found” (short TTL) so repeat lookups skip the DB; optional Bloom filters at very large scale are fine but not required. Default severity if fail: **High** for missing limits on auth or **unauthenticated** email/SMS send; **Medium** for unlimited public ID/search DB lookups or authenticated-but-unbounded invite loops. |
| F-02 | **Verify webhook signatures** `(orig 16)` | Inbound webhooks check provider signatures and timestamps before trusting the body. |
| F-03 | **Webhook replay** | Reject old timestamps; persist event IDs so the same event is not applied twice. |
| F-04 | **Server-side prices** | N/A if the app has no paid checkout or orders. **Pass:** Checkout/order endpoints accept **product or plan ID + quantity** (or provider **Price ID**) only; the server looks up unit price, discounts, tax, and currency from your catalog or payment provider — **ignore** any browser-sent `price`, `amount`, `discount`, `unit_amount`, hidden inputs, JSON fields, or query parameters (`req.body.amount`, `price_data`, etc.). The payment provider is charged the **server-computed** total; fulfilment and payment webhooks verify **amount actually paid** before granting access or shipping goods. **Fail:** Handler charges client-supplied amount, uses editable checkout form price, or grants Pro/order on webhook without matching paid amount. **Fix:** Server-side lookup; strip client money fields; assert `amount_total` / `amount_paid` on webhook. Default severity if fail: **Critical** for client-controlled price or discount. |
| F-05 | **Idempotency and auth cache** | Payment/order POSTs accept idempotency keys. Authenticated HTML/JSON is `Cache-Control: private, no-store`. |
| F-06 | **Server-side entitlement enforcement** | N/A if there are no paid tiers, credits, or trials. **Pass:** Plan, Pro, credits, and trial status come from the **server subscription record** updated only by **verified payment webhooks** (F-02/F-03) or trusted provider APIs — never `localStorage`, `sessionStorage`, unsigned cookies, URL flags (`?pro=1`), or client state like `isPro`. Every premium API route, Server Action, and gated DB query **re-checks** entitlement on the server; hiding paywall UI is not enough. **Fail:** `localStorage.setItem('isPro', true)` unlocks features; API trusts client-sent `plan` or `subscription_status`. **Fix:** Single DB source of truth; server guard on every premium path. Default severity if fail: **High**. |

Hunt: `webhook`, `stripe.webhooks`, `req.body.price`, `req.body.amount`, `unit_amount`, `price_data`, `amount:`, `idempotency`, `ratelimit`, `@upstash/ratelimit`, `express-rate-limit`, `redis.get`, `setex`, `/api/`, `search`, `findUnique`, `invite`, `sendEmail`, `resend.emails.send`, `twilio`, `isPro`, `localStorage.setItem`, `plan ===`, `subscription_status`, `entitlement`.

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
| J-04 | **Agent credentials and human approval** | N/A if the app has no agents, automations, or background AI workers that act on production data. Agents use **dedicated short-lived credentials** (scoped API keys, OIDC workload identity, per-run tokens)—not a human session cookie, personal API key, or `service_role` / admin key copied from `.env`. Production side effects (payments, deletes, mass email, infra changes) require an explicit **human approval** step or break-glass policy documented in code. Each agent run has its **own audit log** (actor, tools, targets, outcome) with secrets redacted. **Pass:** Separate principal per automation; approval gate before irreversible prod actions; log sink without tokens (`path:line`). **Fail:** Chat agent runs as service role; cron uses founder’s JWT; no approval on “delete all users” tool. **Fix:** Issue least-privilege automation identity; wire approval UI or dual-control; structured logging per session. Default severity if fail: **Critical** when service-role or admin creds are shared with agents; **High** for missing approval/logging. |

Hunt: `service_role`, `createAgent`, `langchain`, `tool`, `automation`, `cron`, `worker`, `approval`, `human_in_the_loop`.

### K — Ops and vibe-coding leftovers

| ID | Check | How to verify |
|----|-------|---------------|
| K-01 | **Security review pass** `(orig 11)` | Automated review (SCA/SAST, e.g. `osv-scanner`, semgrep, or vendor security-review) run; critical/high fixed or waived in writing. |
| K-02 | **Audit log and alerting** | Auth failures, admin actions, and payments are logged (no secrets). Error tracker + uptime with PII scrub; someone is paged on 5xx/auth spikes. |
| K-03 | **Rollback plan** | Documented way to revert a deploy (previous image, host rollback, or `git revert` + CI). |
| K-04 | **Vibe leftovers** | No `// TODO: add auth`, commented-out guards, `mockAuth` / `allowAll` / `bypassAuth`, hardcoded passwords, placeholder emails, or debug routes left enabled. |

Hunt: `TODO: add auth`, `FIXME`, `bypassAuth`, `SKIP_AUTH`, `allowAll`, `password123`, `admin@example.com`, `console.log`.

### L — Legal and compliance

These checks are **verifiable from code and the live site** — they are not legal advice. Have a qualified lawyer review privacy-policy, terms, and marketing wording before launch. Mark **N/A** with a reason when the app has no payments, no AI chat, or no personal data.

**Typical exposure (not exact figures):** intentional CCPA violations are often on the order of several thousand dollars each; statutory data-breach damages can reach a few hundred dollars per consumer; FTC civil penalties for fake reviews or negative-option billing are often tens of thousands of dollars per violation; companion-chatbot laws (e.g. California SB 243) may impose per-violation damages — **check current statutes and agency guidance before quoting amounts to a client.**

**Recurring review:** Re-read the privacy policy, terms, and DPA/subprocessor list on a schedule (e.g. quarterly) and whenever you add a new third-party SDK, AI provider, or payment flow.

| ID | Check | How to verify |
|----|-------|---------------|
| L-01 | **Privacy policy discloses what is collected** | N/A if the app collects no personal data. **Pass:** A privacy policy page is linked from signup and the site footer; it lists the personal data the app actually stores (compare DB schema/migrations, signup/profile forms, analytics event payloads). **Fail:** Missing page, lorem ipsum/placeholder, or policy omits fields you persist (email, name, IP, uploads, payment IDs, etc.). **Fix:** Publish an accurate policy and link it consistently. Default severity if fail: **High**. |
| L-02 | **Privacy policy discloses AI use** | N/A if no user content or personal data is sent to an AI model. **Pass:** Policy states that content/data goes to named providers (OpenAI, Anthropic, Google Gemini, etc.), what is sent, and whether providers may retain or train on it. **Fail:** Code calls LLM APIs with user data but policy is silent or vague. **Fix:** Disclose providers, data categories, retention, and opt-out where applicable; have legal review wording. Default severity if fail: **High**. |
| L-03 | **Privacy policy names third-party data collectors** | N/A if no third-party collectors run in prod. **Pass:** Every analytics, ad pixel, session replay, error tracking, payment, and AI SDK loaded or called appears in the policy (cross-check `package.json` / `composer.json`, layout script tags, and live network requests). **Fail:** Active `gtag`, PostHog, Sentry, Stripe.js, etc. without a named disclosure. **Fix:** List each vendor and purpose; maintain a subprocessor/DPA list. Default severity if fail: **High**. |
| L-04 | **Promised deletion actually deletes** | N/A if the app stores no user uploads or accounts to delete. **Pass:** Account/upload delete (or stated retention window) removes objects from object storage and purges CDN/cache within the documented window — not only a DB `deleted_at` / soft-delete flag. Trace the delete handler and storage calls. **Fail:** UI says “deleted” but blobs remain in S3/Supabase/Firebase or public URLs still work. **Fix:** Hard-delete storage; document backup/CDN lag; align policy retention claims with implementation. Default severity if fail: **High**. |
| L-05 | **No fake testimonials or reviews** | N/A if the marketing site shows no testimonials, ratings, user counts, or “as seen in” logos. **Pass:** Quotes, star ratings, “10k users”, and press logos trace to real customers, measured metrics, or licensed assets (evidence in CMS, analytics, or contracts — not hard-coded fiction). **Fail:** Placeholder names, AI personas, invented numbers, or stock logos presented as real social proof. **Fix:** Remove or replace with verifiable claims; legal review marketing copy. Default severity if fail: **High**. |
| L-06 | **Cancelling is as easy as signing up** | N/A if there is no paid subscription. **Pass:** Users can cancel online in no more steps than subscribe (self-serve billing portal or in-app cancel); no forced phone call, email-only maze, or repeated dark-pattern retention screens required to stop billing. **Fail:** Subscribe in two clicks; cancel only via support or hidden settings. **Fix:** Expose Stripe/customer portal or equivalent one-flow cancel; mirror signup friction. Default severity if fail: **High**. |
| L-07 | **Free trials remind before charging** | N/A if no free trial or auto-renewing subscription. **Pass:** Trial signup shows price and first charge date; an email or in-app notification fires before the first charge with an easy cancel path. **Fail:** Silent auto-bill at `trial_end` with no notice. **Fix:** Webhook/email on `trial_will_end` / equivalent; surface cancel in the reminder. Default severity if fail: **Medium**, or **High** if trial users are auto-billed without notice. |
| L-08 | **AI chat handles self-harm safely** | N/A if no chatbot/companion aimed at consumers (especially minors). **Pass:** Self-harm/suicide messages trigger crisis resources (e.g. 988, local hotlines) and stop the normal conversational flow; bots facing minors disclose they are AI. **Fail:** Generic encouragement, no escalation, or human impersonation without disclosure. **Fix:** Moderation layer, crisis templates, minor-facing AI disclosure; legal review. Default severity if fail: **High**. |

Hunt: `privacy`, `privacy-policy`, `/privacy`, `gtag`, `googletagmanager`, `fbq`, `posthog`, `mixpanel`, `segment`, `hotjar`, `clarity`, `sentry`, `intercom`, `stripe`, `openai`, `anthropic`, `@google/generative-ai`, `deleteObject`, `DeleteObjectCommand`, `storage.from(`, `.remove`, `unlink`, `soft_delete`, `deleted_at`, `testimonial`, `reviews`, `rating`, `trusted by`, `cancel`, `cancel_at_period_end`, `billing portal`, `customer_portal`, `trial_end`, `trial_period_days`, `trial_will_end`, `customer.subscription.trial_will_end`, `suicide`, `self-harm`, `crisis`, `988`, `moderation`.

### M — Testing and release readiness

Release gates and automated tests catch regressions before users do; they **do not** prove security or full correctness (keep running security sections A–K and any applicable L checks). These four items extend — not replace — **G-02** (lockfile installs in CI), **K-01** (SCA/SAST only; not app-level unit/integration coverage), **K-03** (rollback assumes CI exists), and **I-01** (backup restore evidence, not perf budgets).

Mark **N/A** with a reason when the repo is docs-only, has no deploy pipeline, or has no user-facing runtime (static marketing site with no checkout).

| ID | Check | How to verify |
|----|-------|---------------|
| M-01 | **Automated release gates** | N/A if nothing is deployed from this repo (pure docs/library with no promotion path). **Pass:** For the environment that receives production traffic, **required** checks on the merge/deploy path include applicable **build**, **typecheck/lint**, and **relevant automated tests** for the change; evidence of **enforcement** — branch protection / deployment rules that block promote on red, plus a **green or intentionally failed-then-fixed run on the proposed commit** (workflow file presence alone is **Fail**). Manual “AI says it works” or unaudited local-only ship does not count. **Fail:** Deploy/promote can proceed with failing checks, checks are optional, or workflows exist but are not required. **Fix:** Wire CI on PR and main; mark checks required; gate Vercel/Netlify/GitHub Actions/harness promote on success. Default severity if fail: **High** when auth, payments, or data-deletion code can ship with bypassable gates; else **Medium**. |
| M-02 | **Meaningful unit and integration tests** | N/A if no application logic (e.g. static site). **Pass:** Tests cover **risky business rules**, **authorization/validation**, **database or service boundaries**, and **success and failure paths**; include **regression tests** for fixed production bugs where feasible. Assertions are **deterministic** and tests **isolate** side effects (mocks/fixtures/fixture DB) — not mandatory 100% line coverage or vague “all paths” claims without cited tests. **Fail:** No tests on critical handlers, only snapshot/trivial tests, or flaky unordered assertions. **Fix:** Add focused tests at service/API layer; pin regressions. **Evidence:** test file paths and latest local or CI results — missing evidence is not Pass. Default severity if fail: **High** for missing coverage on auth/payments/data-loss paths; else **Medium**. |
| M-03 | **Repeatable end-to-end tests** | N/A if no multi-step user journeys. **Pass:** **Repeatable** e2e suite (Playwright/Cypress/etc.) covers applicable **critical journeys** — signup/login/password reset, checkout/cancel, account or data deletion — including **failure and unauthorized** cases; uses **isolated staged users** and **sandbox/test payment** modes. Exploratory UI testing by an AI agent may **supplement** but not replace checked-in e2e. **Fail:** Only manual QA, only happy-path smoke, or prod credentials/charges required to audit. **Fix:** Staging project + test users; run e2e in CI or documented pre-release job. **Never** require real production card charges or irreversible production deletion to mark Pass. Default severity if fail: **High** when payments/auth/deletion lack repeatable e2e; else **Medium**. |
| M-04 | **Performance budgets** | N/A if no performance-sensitive pages/APIs or no documented SLOs. **Pass:** **Documented** budgets for critical user flows (e.g. TTFB, LCP, p95 API latency) name **environment**, **representative workload**, and a **repeatable** measurement method; a **baseline or CI/lighthouse step** enforces or reports against those budgets (not invented universal ms thresholds). **Fail:** No budgets, or load tests only on production without approval. **Fix:** Define budgets in repo docs; run measured checks in staging/CI; avoid unapproved prod stress tests. Default severity if fail: **Medium** (raise if a known slow path blocks core revenue/auth). |

Hunt: `.github/workflows`, `.gitlab-ci`, `circleci`, `vercel.json`, `netlify.toml`, `required_status_checks`, `branch_protection`, `environment: production`, `deploy`, `promote`, `vitest`, `jest`, `pytest`, `phpunit`, `mocha`, `playwright`, `cypress`, `@playwright/test`, `e2e/`, `integration.test`, `__tests__/`, `turbo run test`, `npm test`, `pnpm test`, `coverage`, `lighthouse`, `web-vitals`, `performance-budget`, `k6`, `artillery`, `benchmark`.

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
curl -sI https://APP/privacy

# Deps + secrets (repo)
npx osv-scanner -r . || npm audit --production
composer audit || pip-audit || true
gitleaks detect --no-git -v || true

# CI/CD and test signals (repo — enforcement still needs dashboard evidence)
ls -la .github/workflows 2>/dev/null || true
rg -l "playwright|cypress|vitest|jest|pytest" --glob '*.{json,yml,yaml,ts,js}' . 2>/dev/null | head
```

Record: status code, notable headers (`strict-transport-security`, `content-security-policy`, `access-control-allow-origin`, `set-cookie`, `cache-control`), and whether source maps or verbose errors appear. For **M-01**, also record whether required checks exist on the default branch in the hosting/CI UI (screenshot or API export), not only workflow YAML.

---

## Phase 3 — Severity and verdict

| Severity | Use when |
|----------|----------|
| Critical | Unauth RCE, auth bypass, world-readable secrets/PII, public admin, SQLi/command injection, service-role in the client, client-controlled checkout price or discount (F-04), Google (or other OAuth) login that trusts client-sent `email`/`sub` or an ID token without server-side signature and `iss`/`aud`/`exp`/`email_verified` checks, password hashes or API secrets in API/RSC responses (E-06), public object storage holding backups/config (A-08), agents/automations using human or service-role credentials for prod writes (J-04) |
| High | IDOR, stored XSS, missing RLS on user data, webhook without signature, origin bypass of CDN, password in git, no rate limit on auth or **unauthenticated** email/SMS send (F-01), premium features gated only on client entitlement state (F-06), missing or unvalidated OAuth `state` on Google/social sign-in (callback proceeds without CSRF binding), Google OAuth redirect URIs overly broad or client-controlled without server allowlist, RLS/profile self-update that allows `role`/`plan`/`credits`/`is_admin` bumps (A-07), sensitive routes relying on middleware only (D-12), third-party scripts on login/checkout/admin (B-06), OAuth public client without PKCE (D-13), phishing-capable transactional email HTML (C-06), missing or inaccurate privacy policy for data you collect (L-01), undisclosed AI or third-party data sharing (L-02/L-03), delete path that only soft-deletes storage (L-04), fake testimonials or inflated social proof (L-05), subscription cancel harder than signup (L-06), trial auto-bill without prior notice (L-07), unsafe or undisclosed consumer AI chat (L-08), bypassable or missing release gates on auth/payments/data-loss changes (M-01), no meaningful tests on those paths (M-02), no repeatable e2e for checkout/auth/deletion (M-03) |
| Medium | Missing headers/HSTS, CSRF on cookie session, verbose errors, weak CSP, lockfile missing, backups untested, unlimited public lookup-by-ID or search endpoints that hit the database on every nonexistent-ID miss without rate limits (F-01), unbounded invite/contact email or SMS when authenticated (F-01), trial reminder gaps where notice exists but is weak (L-07), optional CI only (M-01), test gaps on non-critical code (M-02/M-03), missing or unenforced performance budgets (M-04) |
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
  "schemaVersion": "2.5.0",
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
- If a stack does not use SQL/RLS/webhooks/LLM/a VPS/payments/personal data/deploy CI, mark N/A and say why.
- Section L checks are compliance hygiene from code and the live site — not legal advice; recommend lawyer review of policy text.
- Automated tests and green CI **do not** prove security or correctness; they complement A–K and L.
- Never invent Pass; missing evidence for M items (CI run, test paths, e2e report, budget doc) is not Pass. If unsure, Fail or N/A with what to verify next.
- After fixes, re-run only the failed items unless the user asks for a full recheck.
- Do not mark Pass without file:line, config, or a live header/status code.
- Do not write exploit PoCs. Describe the fix and the missing control.
- Active scans beyond polite HTTP/TLS require written authorization in the report Scope.
