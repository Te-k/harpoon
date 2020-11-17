#! /usr/bin/env python
import sys
import json
import datetime
import pytz
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket
from pysecuritytrails import SecurityTrails, SecurityTrailsError


class CommandSecurityTrails(Command):
    """
    # Security Trails

    Query https://securitytrails.com/

    * Get your quota : `harpoon securitytrails quota`
    * Get historical whois info on a domain : `harpoon securitytrails whois DOMAIN`
    * Get Passive DNS data on a domain : `harpoon securitytrails domain DOMAIN`
    * Get Passive DNS data on an IP : `harpoon securitytrails ip IP` (IPv4 only)
    * Get subdomains of a domain : `harpoon subdomains DOMAIN`

    """
    name = "securitytrails"
    description = "Requests SecurityTrails database"
    config = {'SecurityTrails': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('whois', help='Request whois info')
        parser_a.add_argument('DOMAIN', help='DOMAIN to be queried')
        parser_a.set_defaults(subcommand='whois')
        parser_b = subparsers.add_parser('quota', help='Check quota')
        parser_b.set_defaults(subcommand='quota')
        parser_c = subparsers.add_parser('domain', help='Passive DNS info')
        parser_c.add_argument('DOMAIN', help='DOMAIN to be queried')
        parser_c.set_defaults(subcommand='domain')
        parser_d = subparsers.add_parser('ip', help='Passive DNS info')
        parser_d.add_argument('IP', help='Search for passive DNS on an IP')
        parser_d.set_defaults(subcommand='ip')
        parser_e = subparsers.add_parser('subdomains', help='Get subdomains')
        parser_e.add_argument('DOMAIN', help='Domain to be queried')
        parser_e.set_defaults(subcommand='subdomains')
        self.parser = parser


    def run(self, conf, args, plugins):
        client = SecurityTrails(conf['SecurityTrails']['key'])
        if 'subcommand' in args:
            if args.subcommand == 'whois':
                res = client.domain_history_whois(args.DOMAIN)
                print(json.dumps(res['result']['items'], sort_keys=False, indent=4))
            elif args.subcommand == "quota":
                res = client.usage()
                print("Quota : {} / {}".format(
                        res['current_monthly_usage'],
                        res['allowed_monthly_usage']
                    )
                )
            elif args.subcommand == "domain":
                res = client.domain_history_dns(args.DOMAIN)
                print(json.dumps(res['records'], sort_keys=False, indent=4))
            elif args.subcommand == "ip":
                res = client.domain_search({"ipv4": args.IP}, include_ips=True)
                print(json.dumps(res['records'], sort_keys=False, indent=4))
            elif args.subcommand == "subdomains":
                res = client.domain_subdomains(args.DOMAIN)
                for d in res['subdomains']:
                    print(d + '.' + args.DOMAIN)
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        client = SecurityTrails(conf['SecurityTrails']['key'])
        if type == "domain":
            print("[+] Checking SecurityTrails...")
            try:
                res = client.domain_history_dns(query)
                for r in res["records"]:
                    for ip in r["values"]:
                        data["passive_dns"].append({
                            "ip": ip["ip"],
                            "source": "SecurityTrails",
                            "first": parse(r['first_seen']).astimezone(pytz.utc),
                            "last": parse(r['last_seen']).astimezone(pytz.utc)
                        })
            except SecurityTrailsError:
                print("Security Trail request failed")
