# cybersecurity-capstone-part1
Network Reconnaissance and Vulnerability Assessment
[ External Reconnaissance ]
                                   │ (Part 1: Python Recon Tool)
                                   ▼
                       [ Network Boundary Control ]
                                   │ (Part 2: Defensive Rules & Architecture)
                                   ▼
                    [ Web App Audit & Remediation ]
                                   │ (Part 3: Secure Coding & Vulnerability Fixes)
                                   ▼
                 [ AI/ML Threat Detection & Threat Intel ]
                                     (Part 4: ML Classifier + VT/ip-api Integration)
                                     Part 1: Structured Reconnaissance Tool (Code & GitHub Repo)
Key Requirements
Objective: Automated reconnaissance script performing port scanning, banner grabbing, and service enumeration against an authorized target.

Format: Public GitHub repository containing recon.py and README.md.
import socket
import json
import sys
import argparse
from datetime import datetime

def scan_port(target_ip, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                # Banner grab
                try:
                    s.sendall(b'HEAD / HTTP/1.1\r\nHost: ' + target_ip.encode() + b'\r\n\r\n')
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                except Exception:
                    banner = "No banner returned"
                return {"port": port, "status": "OPEN", "banner": banner[:100]}
    except Exception as e:
        return {"port": port, "status": "ERROR", "error": str(e)}
    return None

def main():
    parser = argparse.ArgumentParser(description="Automated Reconnaissance & Port Scanner")
    parser.add_argument("--target", required=True, help="Target IP or Domain")
    parser.add_argument("--ports", default="22,80,443,8080", help="Comma-separated list of ports")
    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(",")]
    print(f"[*] Starting scan against target: {args.target} at {datetime.utcnow().isoformat()}Z")
    
    results = []
    for port in ports:
        res = scan_port(args.target, port)
        if res:
            results.append(res)
            print(f"[+] Port {port}: OPEN | Banner: {res['banner']}")

    # Save formatted text/JSON output
    with open("scan_results.json", "w") as f:
        json.dump({"target": args.target, "timestamp": str(datetime.utcnow()), "results": results}, f, indent=2)
    print("[*] Scan completed. Saved to scan_results.json")

if __name__ == "__main__":
    main()
    
