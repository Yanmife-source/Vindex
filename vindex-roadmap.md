# Vindex — Roadmap & Reference

No deadline. Find the nearest unchecked box, do only that, ignore the rest.

## Phases

### Phase 1 — Foundation (done)
- [x] Fetch URL, print status + headers
- [x] Header checks (CSP, X-Frame-Options, HSTS) → ScanResult struct
- [x] Reflected XSS test against common param names
- [x] Real input-field discovery via HTML parsing (`golang.org/x/net/html`)
- [x] `-e` flag gating active tests

### Phase 2 — Known limitations to just accept for now (not bugs)
- [ ] SPA/JS-rendered pages (Juice Shop, Angular/React sites) won't show real content or dynamically-injected inputs to a plain HTTP fetch — needs a headless browser (`chromedp`) later, not now
- [ ] Fields with no `name` attribute can't be tested via query-string injection — `name` is the only attribute actually submitted in a request; `id`/`class` are irrelevant to this
- [ ] Base URL ≠ where forms live (e.g. jumia.com vs jumia.com/catalog) — needs a crawler, see Phase 4

### Phase 3 — Structured reporting
- [ ] `Finding` struct: severity, description, evidence, URL
- [ ] All checks append to `[]Finding` instead of printing directly
- [ ] Print one formatted report at the end

### Phase 4 — Crawling (separate feature from form discovery)
- [ ] Fetch homepage, extract `<a href>` links (same HTML tokenizer approach as input discovery, looking for `a` tags instead of `input`)
- [ ] Filter to same-domain links only
- [ ] Run form discovery + checks on each discovered page (limit depth to 1-2 links, or it never stops)

### Phase 5 — Concurrency
- [ ] Independent checks (headers, path enumeration) → separate goroutines
- [ ] Discovery→injection pipeline stays sequential internally, but that whole pipeline runs as ONE goroutine alongside the others

### Phase 6 — More passive checks (safe, no -e flag needed)
- [ ] Cookie flags: missing `Secure` / `HttpOnly` / `SameSite`
- [ ] CORS misconfig: reflected `Origin` or wildcard `Access-Control-Allow-Origin`
- [ ] Server/tech disclosure via `Server` / `X-Powered-By` headers
- [ ] Missing `X-Content-Type-Options: nosniff`
- [ ] `robots.txt` / `sitemap.xml` disclosure
- [ ] Dangerous HTTP methods enabled (`OPTIONS` request, check for `PUT`/`DELETE`/`TRACE`)

### Phase 7 — Subdirectory/path enumeration
- [ ] Hardcoded starter list (~10 common paths), flag `200` and `403` responses
- [ ] Later: load wordlist from external `.txt` file instead of hardcoding

### Phase 8 — Growing OWASP coverage (ongoing, never "finishes")
- [ ] SQLi (timing/error-based)
- [ ] IDOR (sequential ID testing)
- [ ] Open redirect

## OWASP Top 10:2025 — honest mapping (not all of these are scanner-testable)

| Category | Can Vindex realistically test this? |
|---|---|
| A01 Broken Access Control (incl. SSRF) | Partially — test known SSRF-prone params, try accessing resources without auth |
| A02 Security Misconfiguration | **Yes** — this is what your header checks already are |
| A03 Software Supply Chain Failures | **No** — different tool category entirely (dependency/SCA scanning, not web scanning) |
| A04 Cryptographic Failures | Partially — check for weak/expired TLS certs, HTTP-only pages |
| A05 Injection | **Yes** — XSS (done), SQLi (planned) |
| A06 Insecure Design | **No** — requires human threat-modeling, not black-box testing |
| A07 Authentication Failures | Partially — check cookie flags, test default credentials on known login paths |
| A08 Software/Data Integrity Failures | Partially — check for missing Subresource Integrity on scripts |
| A09 Logging & Alerting Failures | **No** — invisible from outside the system entirely |
| A10 Mishandling Exceptional Conditions | Partially — send malformed input, check for stack traces/error disclosure in response |

Takeaway: don't aim for "all 10 categories checked." Aim for the ones marked Yes/Partially, in the order they appear in Phase 8 onward. Three of the ten were never buildable as a pure external scanner — that's not a gap in your skill, it's the nature of black-box testing.

## When overwhelmed
Close everything except this file. Find the topmost unchecked box. Do only that.