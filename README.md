# Vindex 🛡️

**Vindex** (Latin for *Defender*) is a web vulnerability scanner written in Go, built incrementally — one vulnerability class at a time — while learning the language itself.

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
./vindex <target-url>
```

## Why this project exists
Built as a way to learn Go through a real, ongoing project rather than tutorials — each new check is also a reason to learn a new part of the language (structs, concurrency, error handling, etc.), documented as I go.

## ⚠️ Disclaimer
Vindex is intended for authorized security testing and educational purposes only. Only run it against systems you own or have explicit written permission to test.