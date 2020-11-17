#! /usr/bin/env python
import sys
import json
import datetime
import pytz
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket
from dnsdb import Dnsdb


class DnsDbTotal(Command):
    """
    # Farsight DnsDB

    * On a domain : `harpoon dnsdb domain DOMAIN`
    * On an IP : `harpoon dnsdb ip IP`
    """
    name = "dnsdb"
    description = "Requests Farsight DNSDB"
    config = {'Dnsdb': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('ip', help='Request passive DNS info on an IP address')
        parser_a.add_argument('IP',  help='IP to be queried')
        parser_a.set_defaults(subcommand='ip')
        parser_b = subparsers.add_parser('domain', help='Request passive DNS info on a domain')
        parser_b.add_argument('DOMAIN',  help='DOMAIN to be queried')
        parser_b.set_defaults(subcommand='domain')
        self.parser = parser


    def run(self, conf, args, plugins):
        dnsdb = Dnsdb(conf['Dnsdb']['key'])
        if 'subcommand' in args:
            if args.subcommand == "domain":
                results = dnsdb.search(name=args.DOMAIN)
                if results.status_code != 200:
                    print("Request failed : status code {}".format(results.status_code))
                else:
                    for r in results.records:
                        print("{}\t{}\t{}\t{}".format(
                            r['rrtype'],
                            r['time_first'],
                            r['time_last'],
                            "/ ".join(r['rdata'])
                        ))
            elif args.subcommand == "ip":
                results = dnsdb.search(ip=args.IP)
                if results.status_code != 200:
                    print("Request failed : status code {}".format(results.status_code))
                else:
                    for r in results.records:
                        print("{}\t{}\t{}\t{}".format(
                            r["rrtype"],
                            r["time_first"],
                            r["time_last"],
                            r["rrname"]
                        ))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        if type == "domain":
            print("[+] Checking DNSdb...")
            dnsdb = Dnsdb(conf['Dnsdb']['key'])
            results = dnsdb.search(name=query)
            if results.status_code != 200:
                print("Request failed : status code {}".format(results.status_code))
            else:
                for r in results.records:
                    if r['rrtype'] in ['A', 'AAAA']:
                        for ip in r['rdata']:
                            data["passive_dns"].append({
                                "ip": ip.strip(),
                                "first": parse(r['time_first']).astimezone(pytz.utc),
                                "last": parse(r['time_last']).astimezone(pytz.utc),
                                "source": "DNSdb"
                            })
        elif type == "ip":
            print("[+] Checking DNSdb...")
            dnsdb = Dnsdb(conf['Dnsdb']['key'])
            results = dnsdb.search(ip=query)
            if results.status_code != 200:
                if results.status_code != 404:
                    print("Request failed : status code {}".format(results.status_code))
            else:
                for r in results.records:
                    if r['rrtype'] in ['A', 'AAAA']:
                        data["passive_dns"].append({
                            "domain": r["rrname"].strip(),
                            "first": parse(r['time_first']).astimezone(pytz.utc),
                            "last": parse(r['time_last']).astimezone(pytz.utc),
                            "source": "DNSdb"
                        })


