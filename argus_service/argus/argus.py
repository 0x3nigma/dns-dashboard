#!/usr/bin/env python3
"""
argus.py — A CLI tool for DNS querying, monitoring, and analysis.

Features:
  - Query any DNS record type with TTL and response time
  - Monitor a domain for record changes in real time
  - Check DNSSEC status
  - Compare responses from Cloudflare (1.1.1.1) and Google (8.8.8.8)
  - JSON output mode for programmatic use (--json flag)

Usage:
  python3 argus.py <domain> [record_type] [options]

Examples:
  python3 argus.py google.com A
  python3 argus.py google.com MX --nameserver 1.1.1.1
  python3 argus.py google.com A --monitor --interval 5
  python3 argus.py google.com --dnssec --nameserver 8.8.8.8
  python3 argus.py google.com A --compare
  python3 argus.py google.com A --json
"""

import dns.resolver
import dns.exception
import dns.rdatatype
import dns.zone
import dns.query
import argparse
import time
import json


def query_dns(domain, record_type, nameserver=None):
    """Query a DNS record for a domain. Returns a dict."""
    try:
        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]

        start = time.time()
        answers = resolver.resolve(domain, record_type)
        elapsed = time.time() - start

        return {
            "domain"      : domain,
            "record_type" : record_type,
            "nameserver"  : resolver.nameservers[0],
            "ttl"         : answers.ttl,
            "response_ms" : round(elapsed * 1000, 2),
            "records"     : [str(r) for r in answers]
        }

    except dns.resolver.NXDOMAIN:
        return {"error": "NXDOMAIN", "domain": domain}
    except dns.resolver.NoAnswer:
        return {"error": f"No {record_type} record found", "domain": domain}
    except dns.resolver.Timeout:
        return {"error": "Timeout", "domain": domain}
    except dns.rdatatype.UnknownRdatatype:
        return {"error": f"Unknown record type: {record_type}"}
    except dns.exception.DNSException as e:
        return {"error": str(e)}


def check_dnssec(domain, nameserver=None):
    """Check whether a domain has DNSSEC enabled. Returns a dict."""
    try:
        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]

        response = resolver.resolve(domain, 'DNSKEY')

        keys = []
        for rdata in response:
            key_type = "KSK" if rdata.flags == 257 else "ZSK"
            keys.append({
                "type"      : key_type,
                "flags"     : rdata.flags,
                "algorithm" : rdata.algorithm,
                "protocol"  : rdata.protocol
            })

        return {
            "domain"  : domain,
            "enabled" : True,
            "keys"    : keys
        }

    except dns.resolver.NoAnswer:
        return {"domain": domain, "enabled": False, "keys": []}
    except dns.resolver.NXDOMAIN:
        return {"domain": domain, "error": "NXDOMAIN"}
    except dns.exception.DNSException as e:
        return {"domain": domain, "error": str(e)}


def compare_resolvers(domain, record_type):
    """Compare DNS responses between Cloudflare and Google. Returns a dict."""
    resolvers = {
        "cloudflare": "1.1.1.1",
        "google"    : "8.8.8.8"
    }
    results = {}

    for name, ip in resolvers.items():
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ip]
            start = time.time()
            answers = resolver.resolve(domain, record_type)
            elapsed = time.time() - start
            results[name] = {
                "records" : sorted(str(rdata) for rdata in answers),
                "ttl"     : answers.ttl,
                "response_ms": round(elapsed * 1000, 2)
            }
        except dns.exception.DNSException as e:
            results[name] = {"error": str(e)}

    # check if both resolvers returned the same records
    r = [d for d in results.values() if "records" in d]
    match = len(r) == 2 and r[0]["records"] == r[1]["records"]

    return {
        "domain"     : domain,
        "record_type": record_type,
        "results"    : results,
        "match"      : match
    }


def subdomain_enum(domain, wordlist=None):
    """Brute force subdomains. Returns a dict."""
    if wordlist is None:
        wordlist = [
            "www", "mail", "ftp", "ssh", "api", "dev", "staging", "test",
            "admin", "portal", "vpn", "remote", "blog", "shop", "store",
            "support", "help", "docs", "status", "monitor", "internal",
            "jenkins", "gitlab", "github", "jira", "confluence", "smtp",
            "pop", "imap", "ns1", "ns2", "mx", "autodiscover", "webmail"
        ]

    found = []
    resolver = dns.resolver.Resolver()

    for sub in wordlist:
        try:
            subdomain = sub + "." + domain
            answers = resolver.resolve(subdomain, "A")
            found.append({
                "subdomain": subdomain,
                "ip"       : str(answers[0])
            })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.exception.DNSException:
            pass

    return {
        "domain"  : domain,
        "found"   : found,
        "count"   : len(found)
    }


def zone_transfer(domain):
    """Attempt DNS zone transfer. Returns a dict."""
    resolver = dns.resolver.Resolver()

    try:
        answers = resolver.resolve(domain, "NS")
        nameservers = set(str(ns) for ns in answers)
    except dns.exception.DNSException as e:
        return {"domain": domain, "error": str(e)}

    results = {}
    for ns in nameservers:
        try:
            ip_ns = str(resolver.resolve(ns, "A")[0])
            xfr = dns.query.xfr(ip_ns, domain, timeout=5)
            zone = dns.zone.from_xfr(xfr)
            records = [str(name) for name in zone.nodes.keys()]
            results[ns] = {"vulnerable": True, "records": records}
        except Exception as e:
            results[ns] = {"vulnerable": False, "reason": str(e)}

    vulnerable = any(v["vulnerable"] for v in results.values())

    return {
        "domain"    : domain,
        "vulnerable": vulnerable,
        "nameservers": results
    }


def bulk_scan(input_file, output_file="report.json"):
    """Scan multiple domains from a file and export results to JSON."""
    try:
        with open(input_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(json.dumps({"error": f"File '{input_file}' not found"}))
        return

    report = {}
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']

    for domain in domains:
        report[domain] = {}
        resolver = dns.resolver.Resolver()

        for record_type in record_types:
            try:
                start = time.time()
                answers = resolver.resolve(domain, record_type)
                elapsed = time.time() - start
                report[domain][record_type] = {
                    "records" : [str(r) for r in answers],
                    "ttl"     : answers.ttl,
                    "response_ms": round(elapsed * 1000, 2)
                }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.rdatatype.UnknownRdatatype):
                pass
            except dns.exception.DNSException as e:
                report[domain][record_type] = {"error": str(e)}

        try:
            dnssec = resolver.resolve(domain, 'DNSKEY')
            report[domain]['DNSSEC'] = {"enabled": True, "keys": len(dnssec)}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            report[domain]['DNSSEC'] = {"enabled": False}
        except dns.exception.DNSException:
            pass

    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(json.dumps({"status": "done", "output": output_file, "domains": len(domains)}))


def monitor_dns(domain, record_type, nameserver=None, interval=10):
    """Monitor a domain for DNS record changes at a given interval."""
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]

    previous = None
    while True:
        try:
            answers = resolver.resolve(domain, record_type)
            current = sorted(str(rdata) for rdata in answers)

            if previous is None:
                print(json.dumps({"event": "baseline", "records": current}))
                previous = current
            elif current != previous:
                print(json.dumps({"event": "change", "before": previous, "after": current}))
                previous = current
            else:
                print(json.dumps({"event": "unchanged", "records": current}))

        except dns.exception.DNSException as e:
            print(json.dumps({"event": "error", "message": str(e)}))

        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DNS Lookup, Monitor, and Analysis Tool",
        epilog="Example: python3 argus.py google.com A --compare"
    )
    parser.add_argument("domain", nargs="?", help="Domain to query e.g. google.com")
    parser.add_argument("record", nargs="?", default="A", help="Record type e.g. A, MX, TXT, CNAME (default: A)")
    parser.add_argument("--nameserver", help="Custom resolver e.g. 8.8.8.8 or 1.1.1.1", default=None)
    parser.add_argument("--monitor", action="store_true", help="Monitor domain for record changes")
    parser.add_argument("--interval", type=int, default=10, help="Polling interval in seconds (default: 10)")
    parser.add_argument("--dnssec", action="store_true", help="Check if domain has DNSSEC enabled")
    parser.add_argument("--compare", action="store_true", help="Compare responses from Cloudflare and Google")
    parser.add_argument("--axfr", action="store_true", help="Attempt DNS Zone Transfer")
    parser.add_argument("--enum", action="store_true", help="Enumerate subdomains")
    parser.add_argument("--wordlist", help="Wordlist file for subdomain enumeration", default=None)
    parser.add_argument("--bulk", help="Path to file containing list of domains to scan")
    parser.add_argument("--output", help="Output JSON file for bulk scan (default: report.json)", default="report.json")
    parser.add_argument("--json", action="store_true", help="Output result as JSON")

    args = parser.parse_args()

    if args.monitor:
        monitor_dns(args.domain, args.record, args.nameserver, args.interval)
    elif args.bulk:
        bulk_scan(args.bulk, args.output)
    elif args.enum:
        wordlist = None
        if args.wordlist:
            try:
                with open(args.wordlist, "r") as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(json.dumps({"error": f"Wordlist '{args.wordlist}' not found"}))
                exit(1)
        print(json.dumps(subdomain_enum(args.domain, wordlist)))
    elif args.axfr:
        print(json.dumps(zone_transfer(args.domain)))
    elif args.compare:
        print(json.dumps(compare_resolvers(args.domain, args.record)))
    elif args.dnssec:
        print(json.dumps(check_dnssec(args.domain, args.nameserver)))
    else:
        print(json.dumps(query_dns(args.domain, args.record, args.nameserver)))
