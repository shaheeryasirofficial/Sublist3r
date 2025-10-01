#!/usr/bin/env python3
# Nmap Integrator for Subdomains - v1.0
# Integrates Nmap port scanning with subdomain lists (e.g., from Sublist3r).
# Filters live subdomains (DNS + HTTP check), then scans for open ports.
# Usage: python nmap_integrator.py -i subdomains.txt -o nmap_results.xml
# Requires: pip install requests dnspython; nmap installed on system

import argparse
import sys
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import dns.resolver
import dns.exception
import tempfile
import os

def is_dns_live(subdomain):
    """Check if subdomain resolves to an IP."""
    try:
        dns.resolver.resolve(subdomain, 'A')
        return True
    except (dns.exception.DNSException, Exception):
        return False

def is_http_live(subdomain, timeout=5):
    """Check if subdomain responds to HTTP/HTTPS."""
    for protocol in ['http', 'https']:
        url = f"{protocol}://{subdomain}"
        try:
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            if resp.status_code > 0:
                return True
        except requests.RequestException:
            continue
    return False

def check_live(subdomain, dns_only=False, timeout=5):
    """Full live check: DNS + optional HTTP."""
    if not is_dns_live(subdomain):
        return False
    if dns_only:
        return True
    return is_http_live(subdomain, timeout)

def run_nmap_scan(subdomain, ports='top-1000', output_dir=None, output_format='xml'):
    """Run Nmap scan on a subdomain and return results."""
    if output_dir:
        output_file = os.path.join(output_dir, f"{subdomain}_nmap.{output_format}")
    else:
        output_file = f"{subdomain}_nmap.{output_format}"
    
    cmd = [
        'nmap', '-sV', '-sC',  # Service version + script scan
        f'-p{ports}',  # Ports to scan
        f'--open',  # Only show open ports
        f'-o{output_format}', output_file,  # Output format
        subdomain
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # 5-min timeout per host
        if result.returncode == 0:
            print(f"[SCAN] {subdomain}: Scan complete. Output: {output_file}")
            return output_file
        else:
            print(f"[ERROR] {subdomain}: Nmap failed - {result.stderr}")
            return None
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] {subdomain}: Scan timed out")
        return None
    except FileNotFoundError:
        print("[ERROR] Nmap not found. Install Nmap and ensure it's in PATH.", file=sys.stderr)
        sys.exit(1)

def parse_nmap_xml(xml_file):
    """Parse Nmap XML for summary (open ports)."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        host = root.find('host')
        if host is None:
            return []
        ports = []
        for port in host.findall('.//port[@state="open"]'):
            port_id = port.get('portid')
            service = port.find('service')
            service_name = service.get('name') if service is not None else 'unknown'
            ports.append(f"{port_id}/{service_name}")
        return ports
    except ET.ParseError:
        return []

def main():
    parser = argparse.ArgumentParser(description="Integrate Nmap port scanning with subdomain lists.")
    parser.add_argument('-i', '--input', required=True, help="Input file with subdomains (one per line)")
    parser.add_argument('-o', '--output-dir', help="Directory for Nmap output files (default: current dir)")
    parser.add_argument('-t', '--threads', type=int, default=10, help="Threads for live check (default: 10); Nmap is sequential")
    parser.add_argument('--dns-only', action='store_true', help="Only check DNS (faster, skip HTTP)")
    parser.add_argument('--ports', default='top-1000', help="Nmap ports (default: top-1000)")
    parser.add_argument('--timeout', type=int, default=5, help="HTTP timeout in seconds (default: 5)")
    parser.add_argument('--summary', action='store_true', help="Print summary of open ports after scanning")
    args = parser.parse_args()

    # Read subdomains
    try:
        with open(args.input, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Filtering {len(subdomains)} subdomains for live hosts...")

    # Filter live subdomains
    live_subdomains = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check_live, sub, args.dns_only, args.timeout): sub for sub in subdomains}
        for future in as_completed(futures):
            sub = futures[future]
            try:
                if future.result():
                    live_subdomains.append(sub)
                    print(f"[LIVE] {sub}")
                else:
                    print(f"[DEAD] {sub}")
            except Exception as e:
                print(f"[ERROR] {sub}: {e}", file=sys.stderr)

    print(f"[INFO] Found {len(live_subdomains)} live subdomains. Starting Nmap scans...")

    # Create output dir if specified
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)

    # Run Nmap sequentially (to avoid overwhelming the network; parallelize if needed)
    scan_results = {}
    for subdomain in live_subdomains:
        output_file = run_nmap_scan(subdomain, args.ports, args.output_dir)
        if output_file and args.summary:
            open_ports = parse_nmap_xml(output_file)
            if open_ports:
                scan_results[subdomain] = open_ports
                print(f"[PORTS] {subdomain}: {', '.join(open_ports)}")

    if args.summary and scan_results:
        print("\n[SUMMARY] Open Ports by Host:")
        for host, ports in scan_results.items():
            print(f"{host}: {', '.join(ports)}")

    print(f"[COMPLETE] Scanned {len(live_subdomains)} hosts. Check output files for details.")

if __name__ == "__main__":
    main()
