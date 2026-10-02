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

**Run it:**
\`\`\`bash
go run . -e http://localhost:8080/vulnerabilities/xss_r/
\`\`\`

## Why this project exists
Built as a way to learn Go through a real, ongoing project rather than tutorials — each new check is also a reason to learn a new part of the language (structs, concurrency, error handling, etc.), documented as I go.

## ⚠️ Disclaimer
Vindex is intended for authorized security testing and educational purposes only. Only run it against systems you own or have explicit written permission to test.