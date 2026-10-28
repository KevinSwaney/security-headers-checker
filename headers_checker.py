#!/usr/bin/env python3
"""Check a website for the security headers that stop common attacks.

Usage:
    python headers_checker.py https://example.com
    python headers_checker.py --url https://example.com --timeout 10

Checks, in plain terms:
  HSTS: forces the browser to use a secure connection, so traffic cannot
        be downgraded to plain text.
  CSP: limits where the page may load scripts and content from, which
       cuts down cross-site scripting attacks.
  X-Frame-Options: stops other sites framing the page, which blocks
       clickjacking tricks.
  X-Content-Type-Options: stops the browser guessing a file type, which
       blocks some drive-by content attacks.
  Referrer-Policy: limits what browsing details leak to other sites.
  Permissions-Policy: switches off browser features the site does not use.
  HTTPS redirect: an insecure http address must forward to https.

Exit code is 0 when every check passes, 1 otherwise.
Requires Python 3.8 or later. No third party packages.
"""

import argparse
import ssl
import sys
import urllib.error
import urllib.request

CHECKS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
]


def fetch(url, timeout):
    """Fetch headers only, following redirects, without downloading the body."""
    request = urllib.request.Request(url, method="HEAD")
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.headers, response.geturl()
    except urllib.error.HTTPError as error:
        return error.headers, error.geturl()
    except urllib.error.URLError as error:
        raise SystemExit("ERROR: could not reach %s (%s)" % (url, error.reason))


def check(url, timeout=10):
    headers, final_url = fetch(url, timeout)
    lowered = {k.lower(): v for k, v in headers.items()}
    results = []
    for header, label in CHECKS:
        value = lowered.get(header)
        if value:
            results.append((label, "PASS", value.strip()))
        else:
            results.append((label, "FAIL", "header missing"))
    https_ok = final_url.startswith("https://")
    if url.startswith("http://") and https_ok:
        redirect = ("HTTPS redirect", "PASS", "http forwarded to %s" % final_url)
    elif url.startswith("https://") and https_ok:
        redirect = ("HTTPS redirect", "PASS", "already on https")
    else:
        redirect = ("HTTPS redirect", "FAIL", "final URL is %s" % final_url)
    results.append(redirect)
    return results, final_url


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check a URL for security headers.")
    parser.add_argument("url", nargs="?", help="URL to check, e.g. https://example.com")
    parser.add_argument("--url", dest="url_opt", help="URL to check")
    parser.add_argument("--timeout", type=int, default=10, help="request timeout in seconds")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    args = parser.parse_args(argv)
    if args.version:
        print("security-headers-checker 1.0.0")
        return 0
    url = args.url_opt or args.url
    if not url:
        parser.error("a URL is required")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    results, final_url = check(url, args.timeout)
    print("=" * 60)
    print("SECURITY HEADERS REPORT")
    print("Requested: %s" % url)
    print("Final URL: %s" % final_url)
    print("=" * 60)
    passed = 0
    for label, status, detail in results:
        if status == "PASS":
            passed += 1
        print("[%s] %-24s %s" % (status, label, detail))
    print("-" * 60)
    print("%d of %d checks passed" % (passed, len(results)))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
