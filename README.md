# Vindex

A web vulnerability scanner written in Go. Built one vulnerability class at a time, as a hands-on way to learn the language (docs, trial and error, and debugging real problems, no tutorials).

Vindex logs into a target, crawls it, discovers input fields, runs passive security-header analysis on every page it finds, and optionally runs active injection tests. It is developed and tested against [DVWA](https://github.com/digininja/DVWA) running locally. It is an early-stage, learning-driven project, not a production scanner.

## Features

### Passive checks (always on)
Run on **every crawled page**, not just the entry point. No payloads are sent.

- Clickjacking exposure (`X-Frame-Options` / CSP `frame-ancestors`)
- Missing `Content-Security-Policy`
- Missing `Strict-Transport-Security`
- Missing `X-Content-Type-Options: nosniff`
- Missing `Referrer-Policy`
- Cookies missing the `Secure` / `HttpOnly` flags
- `Server` header information disclosure

### Active checks (enabled with `-e`)
Payloads are sent to the target, so only use this on systems you are authorized to test.

| Check | Technique | Status |
|---|---|---|
| Reflected XSS | Injects marker payloads into every discovered field and checks for unescaped reflection | Confirmed on DVWA `xss_r` |
| SQL injection (error-based) | Injects non-destructive SQL payloads, matches database error signatures in the response | Confirmed on DVWA `sqli` (and `brute`) |
| CSRF | Submits state-changing forms with a valid token, then a tampered token, and flags forms that accept both | Implemented, not yet confirmed (see Known gaps) |

XSS, SQLi and CSRF checks run **concurrently** with goroutines and a `sync.WaitGroup`. Each check writes to its own result variable, and results are merged after `Wait()`, so no mutex is needed.

### Discovery and plumbing
- **Authenticated session handling:** automated login, CSRF token extraction, and security-level configuration, backed by a cookie jar.
- **Crawler:** same-host link following, relative URL resolution (including `<base href>`), de-duplication, and safety exclusions for session-destroying and state-changing links (`logout`, `setup`).
- **`robots.txt` discovery:** extracts `Disallow:` paths and feeds them into the crawl list.
- **Input field discovery:** extracts form fields and their default values per page, so injection requests include every field the application expects.
- **Structured findings:** every check returns a unified `Finding{Type, URL, Param, Payload, Signature}`, and the report is kept separate from diagnostic logging.
- **Logging:** `log/slog` with a `-v` flag for debug-level output.

## Installation

Requires Go 1.21 or later (for `log/slog`).

```bash
git clone https://github.com/Yanmife-source/Vindex
cd Vindex
go build -o vindex .
```

## Usage

```bash
./vindex [-e] [-v] <target-url>
```

| Flag | Description |
|---|---|
| `-e` | Enable active exploitation checks (XSS, SQLi, CSRF). Without it, only passive checks run. |
| `-v` | Verbose output (debug-level logging). |

### Setting up a test target

```bash
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa
```

Open `http://localhost:8080/setup.php`, click **Create / Reset Database**, then run:

```bash
go run . -e -v http://localhost:8080/vulnerabilities/sqli/
```

The login flow is currently hardcoded to DVWA's default credentials.

### Example output

```
Scan complete — 3 finding(s)

[XSS]  http://localhost:8080/vulnerabilities/xss_r/ — param="name"
[SQLi] http://localhost:8080/vulnerabilities/sqli/ — param="id"
[SQLi] http://localhost:8080/vulnerabilities/brute/ — param="username"
```

The `brute/` hit is a genuine finding: DVWA's low-security login form concatenates `username` into its SQL query, even though it isn't that page's advertised vulnerability.

## Project structure

```
main.go      Orchestration: session -> crawl -> robots -> fields -> checks -> report
auth.go      Login, security level, CSRF token handling, shared HTTP client
crawl.go     Single-page link extraction and URL resolution
headers.go   Authenticated fetch helper and passive header analysis
inject.go    Field discovery, XSS and SQLi checks, concurrent orchestration
csrf.go      Token-based CSRF check
```

Currently a single `package main`. Splitting into `core` / `vulns` packages is planned.

## Engineering notes

Debugging notes from building this, kept because the failure modes are more instructive than the features.

**Silent false negatives are the real danger.**
For days the scanner missed an XSS that manual testing confirmed. The crawler followed every same-domain link, including `Logout`, which destroyed the authenticated session mid-crawl. Every check after that ran on a dead session and produced a clean-looking, meaningless "no vulnerabilities found". The fix was to exclude session-destroying links, and the lesson was that a scanner should be built to fail loudly.

**A scanner can damage its own target.**
Two separate bugs caused DVWA to "keep resetting". One SQLi payload was a literal `DROP TABLE`, which really executed and dropped the users table. Separately, DVWA's `csrf/` and `captcha/` pages are password-change forms, so injection testing was silently overwriting the admin password. Destructive payloads were removed, and state-changing pages are now excluded from injection tests while remaining visible to the CSRF check.

**Smaller bugs worth remembering:**
- `slog.SetDefault()` was never called, so the `-v` handler was built but never used by package-level `slog.Debug()` calls.
- The crawl de-duplication map was declared inside the loop, so it reset every iteration.
- Relative links were resolved against an empty string when no `<base>` tag existed. The fix was to use `resp.Request.URL` as the default base.
- Merging error slices with `append(a, b...)` risks corrupting a shared backing array. Results are now merged into a fresh slice.

## Known gaps

- **CSRF check is unverified.** The success-string match is a guess and has not been confirmed against DVWA's real response. It also has no password-restore step, so a positive finding would leave the admin password changed.
- **GET only.** Most real-world forms use POST. This is the largest gap for use beyond DVWA.
- **Auth, exclusions and error signatures are DVWA-specific** (hardcoded credentials and login flow, one database engine's error messages).
- **No blind SQLi.** `sqli_blind/` needs time-based detection, which is a different technique from error matching.
- **No rate limiting or politeness controls.**
- **No JavaScript rendering.** Server-rendered pages only.
- **No automated tests yet.**

## Roadmap

- [ ] Verify the CSRF check and add a password-restore step
- [ ] Grouped report output: active findings first, passive findings collapsed per header with a page count
- [ ] Missing-CSRF-token check for state-changing forms with no token field
- [ ] Breadth-first multi-page crawler (`crawlSite` with depth limit)
- [ ] Time-based blind SQLi detection
- [ ] POST support and generalized authentication
- [ ] `URLFetcher` interface so checks can be unit-tested with fake responses
- [ ] `core` / `vulns` package split
- [ ] Further coverage: IDOR, open redirect, directory enumeration
- [ ] Headless-browser support (chromedp) for SPAs and DOM XSS

## Disclaimer

Vindex is intended for authorized security testing and education only. Only run it against systems you own or have explicit written permission to test. Active mode sends real payloads and can modify or damage the target.