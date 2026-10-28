# Security Headers Checker

## The business risk first

Most website attacks do not start by breaking encryption. They start by tricking a visitor's browser: loading a malicious script, framing a real page inside a fake one, or downgrading a secure connection. Each trick has a cheap, well known defence, a header the server sends with every page. When those headers are missing, the business carries the risk and the customer pays for it in fraud, account takeover, or a damaged reputation.

This tool checks a site in seconds and prints a clear pass or fail report, so a missing defence becomes a decision, not a guess.

## What it checks

- **HSTS (Strict Transport Security):** forces browsers to use a secure connection, so traffic cannot be downgraded to plain text.
- **CSP (Content Security Policy):** limits where the page may load scripts and content from, cutting down script injection attacks.
- **X-Frame-Options:** stops other sites framing the page, blocking clickjacking tricks.
- **X-Content-Type-Options:** stops the browser guessing a file type, blocking some drive-by content attacks.
- **Referrer-Policy:** limits what browsing details leak to other sites.
- **Permissions-Policy:** switches off browser features the site does not use.
- **HTTPS redirect:** an insecure address must forward visitors to the secure version.

## Run it

```bash
python headers_checker.py https://example.com
```

Example output:

```
[PASS] HSTS                     max-age=31536000; includeSubDomains
[FAIL] CSP                      header missing
```

Exit code is 0 when every check passes, 1 otherwise, so it fits in a script or a scheduled check.

## Requirements

Python 3.8 or later. No third party packages. It reads headers only and does not download page content.

## Author

Kevin Swaney, Principal Cybersecurity Engineer. More at [kevintswaney.com](https://kevintswaney.com).
