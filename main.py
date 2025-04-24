import argparse
import json
import time
from pprint import pprint
from urllib.parse import urlparse
from driftweed import Driftweed

# Metadata constants
NAME = 'Driftweed'
VERSION = '1.0.0'
AUTHOR = 'Hesam Aghajani'
CONTACT = 'hesamz3090@gmail.com'
URL = 'https://github.com/hesamz3090/driftweed'
DESCRIPTIONS = 'A Network and Website Information Retrieval Tool'


def banner():
    # Prints a fancy banner with tool info
    print(rf"""
    ____  _       _  __                _ 
    |  _ \(_) __ _| |/ _| ___  ___ _ __| |
    | | | | |/ _` | | |_ / _ \/ _ \ '__| |
    | |_| | | (_| | |  _|  __/  __/ |  |_|
    |____/|_|\__, |_|_|  \___|\___|_|  (_)
          |___/        v{VERSION}

    Author : {AUTHOR}
    Contact: {CONTACT}
    Description: {DESCRIPTIONS}
    """)


def is_valid_url(url):
    # Checks if the URL is valid and contains scheme/netloc
    parsed = urlparse(url)
    return bool(parsed.scheme) and bool(parsed.netloc)


def main():
    parser = argparse.ArgumentParser(description='Driftweed Recon Toolkit')
    parser.add_argument('url', help='Target URL or domain to scan')
    parser.add_argument('--http', action='store_true', help='Enable HTTP status & header check')
    parser.add_argument('--tech', action='store_true', help='Enable technology detection')
    parser.add_argument('--port', action='store_true', help='Enable port scanning')
    parser.add_argument('--whois', action='store_true', help='Enable WHOIS info lookup')
    parser.add_argument('--ip', action='store_true', help='Enable IP info lookup')
    parser.add_argument('--asn', action='store_true', help='Enable ASN info lookup')
    parser.add_argument('--dns', action='store_true', help='Enable DNS record checking')
    parser.add_argument('--screenshot', action='store_true', help='Take screenshot of the page')
    parser.add_argument('--output', type=str, help='Save result to file (JSON format)')
    parser.add_argument('--pretty', action='store_true', help='Print formatted output to console')
    parser.add_argument('--all', action='store_true', help='Enable all available modules')

    args = parser.parse_args()

    # Automatically apply all options if --all is used
    if args.all:
        args.http = args.tech = args.port = args.whois = args.ip = args.asn = args.dns = args.screenshot = True

    # Add scheme if missing (e.g., convert example.com -> https://example.com)
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url

    # Validate the final URL format
    if not is_valid_url(args.url):
        print("[!] Invalid URL. Please include a proper domain (e.g., https://example.com)")
        return

    banner()
    print(f"[*] Target: {args.url}\n")
    start_time = time.time()
    # Create instance with selected scan options
    d = Driftweed(
        url=args.url,
        get_http_status=args.http,
        get_tech_detect=args.tech,
        get_port_scan=args.port,
        get_whois_info=args.whois,
        get_ip_lookup=args.ip,
        get_asn_lookup=args.asn,
        get_screenshot=args.screenshot,
        get_dns_check=args.dns
    )

    # Run scan and handle errors
    try:
        result = d.run()
    except Exception as e:
        print(f"[!] An error occurred during execution: {e}")
        return

    # Output to console
    if args.pretty:
        pprint(result)
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))

    end_time = time.time()
    duration = end_time - start_time
    print(f"Time taken: {duration:.2f} seconds\n")
    # Save result to file
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"\n[✓] Output saved to: {args.output}")
        except IOError as e:
            print(f"[!] Failed to write output file: {e}")


if __name__ == '__main__':
    main()
