# Vindex

A web vulnerability scanner written in Go. Built one vulnerability class at a time, as a hands-on way to learn the language (docs, trial and error, and debugging real problems, no tutorials).

Vindex logs into a target, crawls it breadth-first, discovers input fields, runs passive analysis (security headers and CSRF-token checks) on every page it finds, and optionally runs active injection tests. It is developed and tested against [DVWA](https://github.com/digininja/DVWA) running locally. It is an early-stage, learning-driven project, not a production scanner.

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
- **Potential CSRF:** forms with no anti-CSRF token that either submit via POST or contain two or more password inputs (the typical change-password pattern). This is a heuristic, so findings are labeled "potential".

### Active checks (enabled with `-e`)
Payloads are sent to the target, so only use this on systems you are authorized to test.

| Check | Technique | Status |
|---|---|---|
| Reflected XSS | Injects marker payloads into every discovered field and checks for unescaped reflection | Confirmed on DVWA `xss_r` |
| SQL injection (error-based) | Injects non-destructive SQL payloads, matches database error signatures in the response | Confirmed on DVWA `sqli` (and `brute`) |
| CSRF token validation | Submits a form with its real token, then with a tampered token, and flags forms that accept both | Experimental, not yet confirmed (see Known gaps) |

The active checks run **concurrently** with goroutines and a `sync.WaitGroup`. Each check writes to its own result variable, and results are merged after `Wait()`, so no mutex is needed.

### Discovery and plumbing
- **Authenticated session handling:** automated login, CSRF token extraction, and security-level configuration, backed by a cookie jar.
- **Breadth-first crawler:** queue-based traversal with a configurable depth limit (`-depth`, default 3), same-host link following, relative URL resolution (including `<base href>`), de-duplication, and safety exclusions for session-destroying and state-changing links (`logout`, `setup`).
- **`robots.txt` discovery:** extracts `Disallow:` paths and feeds them into the crawl list.
- **Input field discovery:** extracts form fields and their default values per page, so injection requests include every field the application expects.
- **Grouped report:** vulnerabilities are listed first, and passive findings are collapsed to one line per finding with a page count. `-detail` expands them to per-URL.
- **Structured findings:** every check returns a unified `Finding{Type, URL, Param, Payload, Signature}`, and the report is kept separate from diagnostic logging.
- **Logging:** `log/slog` with a `-v` flag for debug-level output.

## Installation

Requires Go 1.21 or later (for `log/slog`). The one external dependency, [goquery](https://github.com/PuerkitoBio/goquery), is downloaded automatically on build.

```bash
git clone https://github.com/Yanmife-source/Vindex
cd Vindex
go build -o vindex .
```

## Usage

```bash
./vindex [-e] [-v] [-depth N] [-detail] <target-url>
```

| Flag | Default | Description |
|---|---|---|
| `-e` | off | Enable active exploitation checks (XSS, SQLi, CSRF token validation). Without it, only passive checks run. |
| `-v` | off | Verbose output (debug-level logging). |
| `-depth` | 3 | Maximum crawl depth. |
| `-detail` | off | List every URL for passive findings instead of a per-finding summary. |

### Setting up a test target

```bash
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa
```

Open `http://localhost:8080/setup.php`, click **Create / Reset Database**, then run:

```bash
# passive checks only
go run . http://localhost:8080/vulnerabilities/sqli/

# passive + active checks
go run . -e http://localhost:8080/vulnerabilities/sqli/
```

The login flow is currently hardcoded to DVWA's default credentials.

### Example output

Passive run (no `-e`), trimmed:

```
== Vulnerabilities (7) ==
[Potential-CSRF] http://localhost:8080/vulnerabilities/csrf/ — param="No-Token (GET -> http://localhost:8080/vulnerabilities/csrf/)"
[Potential-CSRF] http://localhost:8080/vulnerabilities/upload/ — param="No-Token (POST -> http://localhost:8080/vulnerabilities/upload/)"
[Potential-CSRF] http://localhost:8080/vulnerabilities/xss_s/ — param="No-Token (POST -> http://localhost:8080/vulnerabilities/xss_s/)"
...

== Passive findings (179 across 30 pages) ==
Missing-Header   Referrer-Policy  (30/30 pages)
Info-Disclosure  Server: Apache/2.4.25 (Debian)  (30/30 pages)
Missing-Header   Strict-Transport-Security  (30/30 pages)
Missing-Header   X-Content-Type-Options  (30/30 pages)
Clickjacking     X-Frame-Options/CSP frame-ancestors  (30/30 pages)
Missing-Header   Content-Security-Policy  (29/30 pages)
```

With `-e`, active findings appear in the same section:

```
[XSS]  http://localhost:8080/vulnerabilities/xss_r/ — param="name"
[SQLi] http://localhost:8080/vulnerabilities/sqli/ — param="id"
[SQLi] http://localhost:8080/vulnerabilities/brute/ — param="username"
```

Two results worth explaining:
- The `brute/` SQLi hit is genuine: DVWA's low-security login form concatenates `username` into its SQL query, even though it isn't that page's advertised vulnerability.
- The passive check flags `csrf/`, DVWA's actual CSRF challenge, which has no token at all. Several other forms are flagged too (POST forms with no token). Those are real "no token" findings, but whether each is exploitable depends on other defenses such as `SameSite` cookies.

## Project structure

```
main.go      Orchestration: session -> crawl -> robots -> fields -> checks -> report
auth.go      Login, security level, CSRF token handling, shared HTTP client
crawl.go     Breadth-first crawler, link extraction and URL resolution
headers.go   Authenticated fetch helper and passive checks
inject.go    Field discovery, XSS and SQLi checks, concurrent orchestration
csrf.go      Passive missing-token check and active token-tamper check
```

Currently a single `package main`. Splitting into `core` / `vulns` packages is planned.

## Engineering notes

Debugging notes from building this, kept because the failure modes are more instructive than the features.

**Silent false negatives are the real danger.**
For days the scanner missed an XSS that manual testing confirmed. The crawler followed every same-domain link, including `Logout`, which destroyed the authenticated session mid-crawl. Every check after that ran on a dead session and produced a clean-looking, meaningless "no vulnerabilities found". The fix was to exclude session-destroying links, and the lesson was that a scanner should be built to fail loudly.

**A scanner can damage its own target.**
Two separate bugs caused DVWA to "keep resetting". One SQLi payload was a literal `DROP TABLE`, which really executed and dropped the users table. Separately, DVWA's `csrf/` and `captcha/` pages are password-change forms, so injection testing was silently overwriting the admin password. Destructive payloads were removed, and state-changing pages are now excluded from injection tests while remaining visible to the CSRF checks.

**The HTTP method is a weak signal for "changes state".**
The first version of the passive CSRF check only flagged POST forms, and it missed the one page it was written to catch: DVWA's password-change form submits over GET. The rule now also looks for the structure of the form (two password inputs), which is a better proxy for what the form does than how it submits.

**Smaller bugs worth remembering:**
- `slog.SetDefault()` was never called, so the `-v` handler was built but never used by package-level `slog.Debug()` calls.
- The crawl de-duplication map was declared inside the loop, so it reset every iteration.
- Relative links were resolved against an empty string when no `<base>` tag existed. The fix was to use `resp.Request.URL` as the default base.
- Merging error slices with `append(a, b...)` risks corrupting a shared backing array. Results are now merged into a fresh slice.
- A `return` inside a `goquery` `.Each()` callback only exits the callback, not the enclosing function.

## Known gaps

- **Active CSRF check is experimental.** It only tests forms that already have a token, and DVWA's low-security `csrf/` page has none, so its positive path can't be validated against DVWA. The success-string match is unconfirmed, and it has no password-restore step.
- **Passive CSRF check is a heuristic.** It only recognizes hidden inputs named like `csrf` or `token`, so tokens in a `<meta>` tag or custom header are missed, as are `SameSite` and `Origin` defenses. It also won't flag state-changing forms that use GET and have no password inputs (an email-change form, for example).
- **Injection checks are GET-only.** Most real-world forms use POST. This is the largest gap for use beyond DVWA.
- **Auth, exclusions and error signatures are DVWA-specific** (hardcoded credentials and login flow, one database engine's error messages).
- **No blind SQLi.** `sqli_blind/` needs time-based detection, which is a different technique from error matching.
- **No rate limiting or politeness controls.**
- **No JavaScript rendering.** Server-rendered pages only.
- **No automated tests yet.**

## Roadmap

- [x] Breadth-first crawler with depth limit
- [x] Grouped report output
- [x] Passive missing-CSRF-token check
- [ ] Validate the active CSRF check against a purpose-built vulnerable test server, and add a password-restore step
- [ ] Time-based blind SQLi detection
- [ ] Config file (YAML) for depth, exclusions and credentials
- [ ] Concurrent fetching with a bounded worker pool and rate limiting
- [ ] POST support and generalized authentication
- [ ] `URLFetcher` interface so checks can be unit-tested with fake responses
- [ ] `core` / `vulns` package split
- [ ] Further coverage: IDOR, open redirect, directory enumeration
- [ ] Headless-browser support (chromedp) for SPAs and DOM XSS

## Disclaimer

Vindex is intended for authorized security testing and education only. Only run it against systems you own or have explicit written permission to test. Active mode sends real payloads and can modify or damage the target.