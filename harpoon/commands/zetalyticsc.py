#! /usr/bin/env python
import sys
import json
import re
import pytz
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.utils import unbracket
from zetalytics import Zetalytics


class CommandZetalytics(Command):
    """
    # Zetalytics

    Query Zetalytics API https://zetalytics.com/
    """
    name = "zetalytics"
    description = "Search in Zetalytics database"
    config = {'Zetalytics': ['token']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('cname2qname', help='Search passive dns by CNAME value (target of CNAME record)')
        parser_a.add_argument('CNAME',  help='CNAME value to query (matches subdomains)')
        parser_a.add_argument('--json', '-j', action='store_true', help='Show raw JSON info')
        parser_a.set_defaults(subcommand='cname2qname')
        parser_b = subparsers.add_parser('domain2aaaa', help='Search passive dns by domain for AAAA (IPv6) records')
        parser_b.add_argument('DOMAIN',  help='Domain')
        parser_b.add_argument('--json', '-j', action='store_true', help='Show raw JSON info')
        parser_b.set_defaults(subcommand='domain2aaaa')
        parser_c = subparsers.add_parser('domain2cname', help='Search passive dns by domain for CNAME records')
        parser_c.add_argument('DOMAIN',  help='Domain')
        parser_c.add_argument('--json', '-j', action='store_true', help='Show raw JSON info')
        parser_c.set_defaults(subcommand='domain2cname')
        parser_d = subparsers.add_parser('domain2d8s', help='Search historical d8s records and/or live d8s')
        parser_d.add_argument('DOMAIN',  help='Domain')
        parser_d.set_defaults(subcommand='domain2d8s')
        parser_e = subparsers.add_parser('domain2ip', help='Search passive dns by domain for A (IPv4) records')
        parser_e.add_argument('DOMAIN',  help='Domain')
        parser_e.add_argument('--json', '-j', action='store_true', help='Show raw JSON info')
        parser_e.set_defaults(subcommand='domain2ip')
        parser_f = subparsers.add_parser('domain2malwaredns', help='Search malware dns by domain')
        parser_f.add_argument('DOMAIN',  help='Domain')
        parser_f.set_defaults(subcommand='domain2malwaredns')
        parser_g = subparsers.add_parser('domain2malwarehttp', help='Search malware http by domain')
        parser_g.add_argument('DOMAIN',  help='Domain')
        parser_g.set_defaults(subcommand='domain2malwarehttp')
        parser_h = subparsers.add_parser('domain2mx', help='Search passive dns by domain for MX records')
        parser_h.add_argument('--json', '-j', action='store_true', help='Show raw JSON info')
        parser_h.add_argument('DOMAIN',  help='Domain')
        parser_h.set_defaults(subcommand='domain2mx')
        parser_i = subparsers.add_parser('domain2ns', help='Search passive dns by domain for NS records')
        parser_i.add_argument('--json', '-j', action='store_true', help='Show raw JSON info')
        parser_i.add_argument('DOMAIN',  help='Domain')
        parser_i.set_defaults(subcommand='domain2ns')
        parser_j = subparsers.add_parser('domain2nsglue', help='Search name server glue (IP) records by domain name. NOTE: these are only the glue records found in gTLD zone files and NOT all IP records for every name server domain.')
        parser_j.add_argument('DOMAIN',  help='Domain')
        parser_j.set_defaults(subcommand='domain2nsglue')
        parser_k = subparsers.add_parser('domain2ptr', help='Search passive dns by domain for PTR records')
        parser_k.add_argument('--json', '-j', action='store_true', help='Show raw JSON info')
        parser_k.add_argument('DOMAIN',  help='Domain')
        parser_k.set_defaults(subcommand='domain2ptr')
        parser_l = subparsers.add_parser('domain2txt', help='Search passive dns by domain for TXT records')
        parser_l.add_argument('--json', '-j', action='store_true', help='Show raw JSON info')
        parser_l.add_argument('DOMAIN',  help='Domain')
        parser_l.set_defaults(subcommand='domain2txt')
        parser_m = subparsers.add_parser('domain2whois', help='Search historical whois records')
        parser_m.add_argument('DOMAIN',  help='Domain')
        parser_m.set_defaults(subcommand='domain2whois')
        parser_n = subparsers.add_parser('email_address', help='Search for domains sharing a registration email address or SOA email from passive')
        parser_n.add_argument('EMAIL',  help='Email address')
        parser_n.add_argument('--json', '-j', action='store_true', help='Show raw JSON info')
        parser_n.set_defaults(subcommand='email_address')
        parser_o = subparsers.add_parser('email_domain', help='Search for domains sharing a registration email address domain')
        parser_o.add_argument('EMAIL',  help='Email address')
        parser_o.set_defaults(subcommand='email_domain')
        parser_p = subparsers.add_parser('email_user', help='Search for domains sharing a registration email address or SOA email from passive')
        parser_p.add_argument('EMAIL',  help='Email address')
        parser_p.set_defaults(subcommand='email_user')
        parser_q = subparsers.add_parser('hash2malwaredns', help='Search malware dns by md5 hash')
        parser_q.add_argument('HASH',  help='Md5 hash')
        parser_q.set_defaults(subcommand='hash2malwaredns')
        parser_r = subparsers.add_parser('hash2malwarehttp', help='Search malware http by md5 hash')
        parser_r.add_argument('HASH',  help='Md5 hash')
        parser_r.set_defaults(subcommand='hash2malwarehttp')
        parser_s = subparsers.add_parser('hostname', help='Search passive dns by hostname for mixed resource record types')
        parser_s.add_argument('DOMAIN',  help='Domain name')
        parser_s.set_defaults(subcommand='hostname')
        parser_t = subparsers.add_parser('ip', help='Search passive dns by IP, CIDR, or Range (v6 compatible)')
        parser_t.add_argument('--json', '-j', action='store_true', help='Show raw JSON info')
        parser_t.add_argument('IP',  help='IP or CIDR or IP range')
        parser_t.set_defaults(subcommand='ip')
        parser_u = subparsers.add_parser('ip2malwaredns', help='Search malware dns by IP')
        parser_u.add_argument('IP',  help='IP address or CIDR or range IP')
        parser_u.set_defaults(subcommand='ip2malwaredns')
        parser_v = subparsers.add_parser('ip2malwarehttp', help='Search malware http by IP/CIDR for http://x.x.x.x/ (not the IP a hostname resolved to). These results would not appear in the malware dns data since they do not require a DNS lookup.')
        parser_v.add_argument('IP',  help='IP address or CIDR or range IP')
        parser_v.set_defaults(subcommand='ip2malwarehttp')
        parser_w = subparsers.add_parser('ip2nsglue', help='Search name server glue (IP) records by IP, CIDR, or Range (v6 compatible)')
        parser_w.add_argument('IP',  help='IP address or CIDR or range IP')
        parser_w.set_defaults(subcommand='ip2nsglue')
        parser_x = subparsers.add_parser('mx2domain', help='Search passive dns by MX domain for any domain served by the MX domain')
        parser_x.add_argument('MX',  help='MX server')
        parser_x.set_defaults(subcommand='mx2domain')
        parser_y = subparsers.add_parser('ns2domain', help='Search current zone files and passive DNS for domains served by nameserver. Note: start, end, and tsfield apply only to the passive results. Zone file records are from the most recent snapshot only, and will be excluded if end is less than yesterday')
        parser_y.add_argument('NS',  help='NS server')
        parser_y.set_defaults(subcommand='ns2domain')
        parser_z = subparsers.add_parser('subdomains', help='Search passive dns by domain for a list of subdomains from any record type')
        parser_z.add_argument('DOMAIN',  help='Domain name')
        parser_z.set_defaults(subcommand='subdomains')
        self.parser = parser

    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            zeta = Zetalytics(token=conf['Zetalytics']['token'])
            if args.subcommand == "cname2qname":
                res = zeta.cname2qname(q=unbracket(args.CNAME))
                if args.json:
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    if res['total'] == 0:
                        print("Not found")
                    else:
                        for r in res['results']:
                            print("{:12}{:35} {:20} {}".format(
                                r['last_seen'] if "last_seen" in r else "",
                                r['qname'],
                                r['domain'],
                                r['value']
                            ))
            elif  args.subcommand == "domain2aaaa":
                res = zeta.domain2aaaa(q=unbracket(args.DOMAIN))
                if args.json:
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    if res['total'] == 0:
                        print("Nothing found")
                    else:
                        for r in res['results']:
                            print("{:12} {:30} {}".format(
                                r['last_seen'] if "last_seen" in r else "",
                                r['qname'],
                                r['value']
                            ))
            elif  args.subcommand == "domain2cname":
                res = zeta.domain2cname(q=unbracket(args.DOMAIN))
                if args.json:
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    if res['total'] == 0:
                        print("Nothing found")
                    else:
                        for r in res['results']:
                            print("{:12} {:30} {}".format(
                                r['last_seen'] if "last_seen" in r else "",
                                r['qname'],
                                r['value']
                            ))
            elif  args.subcommand == "domain2d8s":
                res = zeta.domain2d8s(q=unbracket(args.DOMAIN))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "domain2ip":
                res = zeta.domain2ip(q=unbracket(args.DOMAIN))
                if args.json:
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    if res['total'] == 0:
                        print("Nothing found")
                    else:
                        for r in res['results']:
                            print("{:12} {:30} {}".format(
                                r['last_seen'] if "last_seen" in r else "",
                                r['qname'],
                                r['value']
                            ))
            elif  args.subcommand == "domain2malwaredns":
                res = zeta.domain2malwaredns(q=unbracket(args.DOMAIN))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "domain2malwarehttp":
                res = zeta.domain2malwarehttp(q=unbracket(args.DOMAIN))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "domain2mx":
                res = zeta.domain2mx(q=unbracket(args.DOMAIN))
                if args.json:
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    if res['total'] == 0:
                        print("Nothing found")
                    else:
                        for r in res['results']:
                            print("{:12} {:30} {}".format(
                                r['date'],
                                r['qname'],
                                r['value']
                            ))
            elif  args.subcommand == "domain2ns":
                res = zeta.domain2ns(q=unbracket(args.DOMAIN))
                if args.json:
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    if res['total'] == 0:
                        print("Nothing found")
                    else:
                        for r in res['results']:
                            print("{:12} {:30} {}".format(
                                r['date'],
                                r['qname'],
                                r['value']
                            ))
            elif  args.subcommand == "domain2nsglue":
                res = zeta.domain2nsglue(q=unbracket(args.DOMAIN))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "domain2ptr":
                res = zeta.domain2ptr(q=unbracket(args.DOMAIN))
                if args.json:
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    if res['total'] == 0:
                        print("Nothing found")
                    else:
                        for r in res['results']:
                            print("{:12} {:30} {}".format(
                                r['date'],
                                r['qname'],
                                r['value']
                            ))
            elif  args.subcommand == "domain2txt":
                res = zeta.domain2txt(q=unbracket(args.DOMAIN))
                if args.json:
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    if res['total'] == 0:
                        print("Nothing found")
                    else:
                        for r in res['results']:
                            print("{:12} {:30} {}".format(
                                r['date'],
                                r['qname'],
                                r['value']
                            ))
            elif  args.subcommand == "domain2whois":
                res = zeta.domain2whois(q=unbracket(args.DOMAIN))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "email_address":
                res = zeta.email_address(q=unbracket(args.EMAIL))
                if args.json:
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    if res['total'] == 0:
                        print("Nothing found")
                    else:
                        for r in sorted(res['results'], key=lambda x: x['last_ts']):
                            print("{} {} - {:30} - {}".format(
                                r["first_ts"][:10],
                                r["last_ts"][:10],
                                r['d'],
                                r["emails"][0]["addr"]
                            ))
            elif  args.subcommand == "email_domain":
                res = zeta.email_domain(q=unbracket(args.EMAIL))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "email_user":
                res = zeta.email_user(q=unbracket(args.EMAIL))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "hash2malwaredns":
                if not re.fullmatch("[a-fA-F\d]{32}", args.HASH):
                    print("Zetalytics only accept md5 hashes")
                else:
                    res = zeta.hash2malwaredns(q=args.HASH)
                    print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "hash2malwarehttp":
                if not re.fullmatch("[a-fA-F\d]{32}", args.HASH):
                    print("Zetalytics only accept md5 hashes")
                else:
                    res = zeta.hash2malwarehttp(q=args.HASH)
                    print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "hostname":
                res = zeta.hostname(q=unbracket(args.DOMAIN))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "ip":
                res = zeta.ip(q=unbracket(args.IP))
                if args.json:
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    if res['total'] == 0:
                        print("Not found")
                    else:
                        for r in res['results']:
                            print("{} - {} - {}".format(
                                r['date'],
                                r['last_seen'] if "last_seen" in r else "",
                                r['qname']
                            ))
            elif  args.subcommand == "ip2malwaredns":
                res = zeta.ip2malwaredns(q=unbracket(args.IP))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "ip2malwarehttp":
                res = zeta.ip2malwarehttp(q=unbracket(args.IP))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "ip2nsglue":
                res = zeta.ip2nsglue(q=unbracket(args.IP))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "mx2domain":
                res = zeta.mx2domain(q=unbracket(args.MX))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "ns2domain":
                res = zeta.ns2domain(q=unbracket(args.NS))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif  args.subcommand == "subdomains":
                res = zeta.subdomains(q=unbracket(args.DOMAIN))
                print(json.dumps(res, sort_keys=False, indent=4))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        zeta = Zetalytics(token=conf['Zetalytics']['token'])
        if type == "domain":
            print("[+] Checking Zetalytics...")
            res = zeta.domain2ip(q=query)
            if "results" in res:
                for domain in res["results"]:
                    if domain["qname"] == query:
                        data["passive_dns"].append({
                            "ip": domain["value"],
                            "source": "Zetalytics",
                            "first": parse(domain['date']).astimezone(pytz.utc),
                            "last": parse(domain['last_seen']).astimezone(pytz.utc) if "last_seen" in domain else None,
                        })
                    #else:
                        #data["subdomains"].append(domain["qname"])
        elif type == "ip":
            print("[+] Checking Zetalytics...")
            res = zeta.ip(q=query)
            if "results" in res:
                for domain in res["results"]:
                    data["passive_dns"].append({
                        "domain": domain["qname"],
                        "source": "Zetalytics",
                        "first": parse(domain['date']).astimezone(pytz.utc),
                        "last": parse(domain['last_seen']).astimezone(pytz.utc) if "last_seen" in domain else None,
                    })
