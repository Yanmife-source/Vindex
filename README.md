# Vindex 🛡️

**Vindex**  is a web vulnerability scanner written in Go, built incrementally — one vulnerability class at a time — while learning the language itself.

It currently performs passive header analysis and basic active reflected-XSS testing. It is an early-stage, learning-driven project, not a finished tool.

## Current Features
- **Security header analysis:** flags missing `Content-Security-Policy`, `X-Frame-Options`, and `Strict-Transport-Security`, and reports what each absence means (e.g. clickjacking exposure, weaker XSS defense-in-depth, SSL-stripping risk).
- **Reflected XSS testing:** sends a set of test payloads to common parameter names and checks for unescaped reflection in the response.

## Planned
- Structured findings report (not just console output)
- `-e` flag to gate active exploitation attempts separately from passive detection
- Concurrent scanning (goroutines) for faster multi-check runs
- Additional checks: SQLi, IDOR, open redirect, directory exposure
- Headless-browser-based checks for SPA/JS-rendered content and DOM XSS

## Installation
```bash
git clone https://github.com/Yanmife-source/Vindex
cd Vindex
go build -o vindex ./...
```

## Usage
```bash
./vindex [options] <target-url>
```
### Confirmed Reflected XSS (DVWA)
Vindex successfully detected and confirmed reflected XSS on DVWA's `xss_r` challenge, end-to-end: automated login, CSRF token handling, security-level configuration, crawling, form-field discovery, and payload injection, all working together against a real authenticated target.

**A bug worth documenting:** for several days, the scanner reliably failed to detect a vulnerability that manual testing confirmed was there. The root cause: the crawler was following *every* same-domain link it found — including the site's own "Logout" link — which silently destroyed the authenticated session mid-crawl. Every check that ran afterward was unknowingly operating on a dead session, producing a clean-looking but meaningless "no vulnerabilities found" result.

**Fix:** the crawler now explicitly excludes logout/session-destroying links from its traversal. **Lesson:** a scanner's most dangerous failure mode isn't a crash — it's a silent false negative that looks identical to a real clean scan. Worth building deliberate safeguards against destructive actions into any crawler from the start.


### Concurrent injection testing + SQLi detection

XSS and SQLi testing now run **concurrently** via goroutines instead of sequentially — `RunInjectionTests()` fires both checks off in parallel and waits for both to finish before reporting, instead of running XSS to completion and then starting SQLi.

- `check_SQLi_vuln()` — structurally mirrors `check_XSS_vuln()`: sends a list of SQLi payloads against every discovered input field and checks the response body for known SQL error-message signatures (error-based detection).
  **Status: not yet confirmed working.** No hits yet against DVWA's `sqli/` page at low security — still diagnosing whether the signature list doesn't match DVWA's actual error wording, or DVWA isn't surfacing a raw SQL error at all. Documenting this honestly rather than claiming it works.
- `sqli_blind/` is a separate, harder problem — it shows no visible difference between a successful and failed injection, so error-string matching can never catch it by design. That'll need a genuinely different technique later (time-based: a `SLEEP()` payload + measuring response delay).

**Concepts covered:** goroutines (`go func(){}()`), `sync.WaitGroup` (`Add`/`Done`/`Wait`), why result-reading has to happen *after* `Wait()` and never inside the goroutines themselves (race conditions / interleaved output).

**Run it:**
```bash
go run . -e http://localhost:8080/vulnerabilities/sqli/
```

### More passive header/security checks

`check_headers()` now reports on more than just clickjacking and CSP:

- Missing `X-Content-Type-Options: nosniff`
- Missing `Referrer-Policy`
- Cookies missing the `Secure` and/or `HttpOnly` flags
- `Server` header disclosure (e.g. leaking `Apache/2.4.25 (Debian)`)

All of this is passive — no payloads sent, so it runs regardless of the `-e` flag.

### robots.txt discovery

`check_robots()` fetches `robots.txt` and extracts any `Disallow:` paths, surfacing pages that aren't linked anywhere in the crawlable site but are still reachable — useful for finding hidden/forgotten endpoints. Its output is meant to be merged into the crawler's discovered-links list at the call site in `main.go`, not inside `crawl()` itself, to keep crawling and robots-parsing as separate responsibilities.

**Run it:**
```bash
go run . http://localhost:8080/
```

## Why this project exists
Built as a way to learn Go through a real, ongoing project rather than tutorials — each new check is also a reason to learn a new part of the language (structs, concurrency, error handling, etc.), documented as I go.

## ⚠️ Disclaimer
Vindex is intended for authorized security testing and educational purposes only. Only run it against systems you own or have explicit written permission to test.