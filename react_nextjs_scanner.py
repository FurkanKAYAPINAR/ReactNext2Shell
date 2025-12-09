#!/usr/bin/env python3
"""
react_nextjs_scanner.py - Cross-platform CLI scanner for indicators of CVE-2025-55182 and CVE-2025-66478
Safe, non-exploitative: heuristic checks only (HTTP probes, headers, HTML/JS fingerprints).
Returns simple English results: VULNERABLE / NOT VULNERABLE with reasoning.

Author: FurkanKAYAPINAR
GitHub: github.com/FurkanKAYAPINAR
LinkedIn: linkedin.com/in/FurkanKAYAPINAR

Usage examples:
  python3 react_nextjs_scanner.py http://127.0.0.1:3000
  python3 react_nextjs_scanner.py 192.168.1.10 --port 8080 --insecure
  python3 react_nextjs_scanner.py https://example.com --timeout 5

Notes:
 - This tool does NOT perform exploits. It is intended for safe reconnaissance in your own lab.
 - Heuristics can yield false positives/negatives. Treat findings as indicators, not proofs.
"""

from __future__ import annotations
import argparse
import sys
import re
import json
from urllib.parse import urlparse, urlunparse
import requests
from requests.exceptions import RequestException, SSLError, Timeout, ConnectionError

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH = True
    console = Console()
except Exception:
    RICH = False
    console = None

DEFAULT_TIMEOUT = 6.0

def build_base_url(target: str, port: int|None) -> str:
    # Accept target like "http://host", "host", "host:port", or "https://host"
    parsed = urlparse(target if '://' in target else f'//{target}', scheme='http')
    scheme = parsed.scheme or 'http'
    netloc = parsed.netloc or parsed.path
    hostname = netloc.split(':')[0]
    final_port = port or (parsed.port)
    if final_port:
        netloc = f"{hostname}:{final_port}"
    return urlunparse((scheme, netloc, '', '', '', ''))

def safe_get(url: str, timeout=DEFAULT_TIMEOUT, verify=True, headers=None):
    try:
        r = requests.get(url, timeout=timeout, verify=verify, headers=headers or {})
        return r
    except (SSLError, Timeout, ConnectionError, RequestException) as e:
        return e

def probe_targets(base_url: str, timeout: float, verify: bool):
    endpoints = [
        "/", "/api/users", "/api/test", "/api", "/index.html", "/package.json",
        "/_next/static", "/_next/static/chunks", "/_next/static/chunks/pages", "/_next/static/*",
    ]
    results = {}
    for ep in endpoints:
        url = base_url.rstrip('/') + ep if not ep.startswith('/') else base_url.rstrip('/') + ep
        try:
            r = safe_get(url, timeout=timeout, verify=verify)
            results[ep] = r
        except Exception as e:
            results[ep] = e
    return results

def analyze_responses(responses: dict) -> dict:
    findings = {
        "cve_2025_55182": {"indicator": False, "evidence": []},
        "cve_2025_66478": {"indicator": False, "evidence": []},
        "notes": []
    }

    # Helper patterns
    next_js_pattern = re.compile(r"Next\.js|next.js|_next/|__NEXT_DATA__", re.IGNORECASE)
    react_server_dom_pattern = re.compile(r"react-server-dom", re.IGNORECASE)
    next_version_pattern = re.compile(r'"next"\s*:\s*"([^"]+)"')
    react_version_pattern = re.compile(r'"react"\s*:\s*"([^"]+)"')

    for ep, resp in responses.items():
        if isinstance(resp, Exception):
            continue
        if not hasattr(resp, "status_code"):
            continue
        txt = ""
        try:
            txt = resp.text or ""
        except Exception:
            txt = ""
        # Check headers for Next.js or Vercel hints
        server_hdr = resp.headers.get("server","") or resp.headers.get("Server","")
        x_powered = resp.headers.get("x-powered-by","") or resp.headers.get("X-Powered-By","")
        # General Next.js heuristics
        if next_js_pattern.search(txt) or "/_next/" in (resp.url or "") or "_next" in txt:
            findings["cve_2025_66478"]["indicator"] = True
            findings["cve_2025_66478"]["evidence"].append(f"Next.js fingerprint on {ep} (body/url contains '_next' or '__NEXT_DATA__')")
        if "vercel" in server_hdr.lower() or "vercel" in x_powered.lower():
            findings["cve_2025_66478"]["indicator"] = True
            findings["cve_2025_66478"]["evidence"].append(f"Server/Powered-by header suggests Vercel on {ep}: '{server_hdr or x_powered}'")
        # Look for package.json exposures (don't request other sensitive files beyond package.json)
        if ep.endswith("package.json") and resp.status_code == 200:
            # try parse json to extract dependencies if any
            try:
                pkg = resp.json()
                deps = pkg.get("dependencies", {})
                devdeps = pkg.get("devDependencies", {})
                merged = {**deps, **devdeps}
                if any(k.startswith("react-server-dom") for k in merged.keys()):
                    findings["cve_2025_55182"]["indicator"] = True
                    findings["cve_2025_55182"]["evidence"].append("Exposed package.json lists react-server-dom package")
                if "next" in merged:
                    findings["cve_2025_66478"]["indicator"] = True
                    findings["cve_2025_66478"]["evidence"].append(f"Exposed package.json lists next@{merged.get('next')}")
            except Exception:
                pass
        # Check for react-server-dom references in served JS or HTML
        if react_server_dom_pattern.search(txt):
            findings["cve_2025_55182"]["indicator"] = True
            findings["cve_2025_55182"]["evidence"].append(f"react-server-dom reference in response body at {ep}")
        # Check for scripts or manifests indicating Next.js versions
        m_next = next_version_pattern.search(txt)
        if m_next:
            ver = m_next.group(1)
            findings["cve_2025_66478"]["indicator"] = True
            findings["cve_2025_66478"]["evidence"].append(f"Detected next version string in response: {ver} at {ep}")
        m_react = react_version_pattern.search(txt)
        if m_react:
            ver = m_react.group(1)
            findings["cve_2025_55182"]["evidence"].append(f"Detected react version string: {ver} at {ep}")
        # Check for common API behavior used in our testlab
        if ep in ("/api/users", "/api/test") and resp.status_code == 200:
            # If returns JSON and structure matches the test lab, flag as possible
            try:
                js = resp.json()
                if isinstance(js, list) and any(isinstance(i, dict) for i in js):
                    findings["cve_2025_55182"]["indicator"] = True
                    findings["cve_2025_55182"]["evidence"].append(f"API {ep} returned JSON list of objects (common lab fingerprint)")
                if isinstance(js, dict) and "message" in js:
                    findings["cve_2025_66478"]["evidence"].append(f"API {ep} returned message key which matches test route fingerprint")
            except Exception:
                pass
        # Header based heuristics for React Server Components (RSC)
        if "x-rsc" in (k.lower() for k in resp.headers.keys()):
            findings["cve_2025_55182"]["indicator"] = True
            findings["cve_2025_55182"]["evidence"].append(f"Found x-rsc header on {ep}")

    # Add notes based on combined heuristics
    if findings["cve_2025_55182"]["indicator"] and not findings["cve_2025_55182"]["evidence"]:
        findings["cve_2025_55182"]["evidence"].append("General RSC indicators detected (heuristic)")
    if findings["cve_2025_66478"]["indicator"] and not findings["cve_2025_66478"]["evidence"]:
        findings["cve_2025_66478"]["evidence"].append("General Next.js indicators detected (heuristic)")

    return findings

def print_report(target: str, findings: dict):
    lines = []
    def add(s=""): lines.append(s)
    add(f"Scan target: {target}")
    add("Summary results:")
    for cve, info in (("CVE-2025-55182", findings["cve_2025_55182"]),
                      ("CVE-2025-66478", findings["cve_2025_66478"])):
        status = "VULNERABLE" if info.get("indicator") else "NOT VULNERABLE"
        add(f"- {cve}: {status}")
        if info.get("evidence"):
            for ev in info["evidence"]:
                add(f"    • {ev}")
    if findings.get("notes"):
        add("\nNotes:")
        for n in findings["notes"]:
            add(f" - {n}")

    output = "\n".join(lines)
    if RICH and console:
        panel = Panel(output, title="Scan Report", expand=False)
        console.print(panel)
    else:
        print(output)

def scan_single_target(target, port, timeout, insecure, verbose):
    base_url = build_base_url(target, port)
    if verbose and RICH and console:
        console.log(f"[blue]Probing base URL[/blue]: {base_url}")
    elif verbose:
        print(f"Probing base URL: {base_url}")
        
    responses = probe_targets(base_url, timeout=timeout, verify=(not insecure))
    findings = analyze_responses(responses)
    print_report(base_url, findings)
    return base_url, findings

def main():
    parser = argparse.ArgumentParser(description="Safe CVE indicator scanner (heuristic, non-exploitative).")
    parser.add_argument("target", nargs='?', help="Target URL or IP (e.g. http://host, host, host:port, https://host)")
    parser.add_argument("-f", "--file", help="Input file containing list of targets (one per line)")
    parser.add_argument("--port", type=int, help="Optional port to override")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Request timeout seconds (default: 6)")
    parser.add_argument("--insecure", action="store_true", help="Allow insecure TLS (skip verification)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output for debugging")
    args = parser.parse_args()

    targets = []
    if args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
    elif args.target:
        targets = [args.target]
    else:
        parser.print_help()
        sys.exit(1)

    vulnerable_findings = []

    print(f"[*] Starting scan on {len(targets)} targets...\n")

    for t in targets:
        try:
            url, res = scan_single_target(t, args.port, args.timeout, args.insecure, args.verbose)
            if res["cve_2025_55182"]["indicator"] or res["cve_2025_66478"]["indicator"]:
                vulnerable_findings.append(url)
        except Exception as e:
            print(f"[!] Error scanning {t}: {e}\n")

    if args.file:
        print("\n" + "="*40)
        print("BULK SCAN SUMMARY")
        print("="*40)
        if vulnerable_findings:
            print(f"Found {len(vulnerable_findings)} potentially vulnerable targets:")
            for v in vulnerable_findings:
                print(f" - {v}")
        else:
            print("No vulnerable targets found in the list.")
        print("="*40)

if __name__ == '__main__':
    main()
