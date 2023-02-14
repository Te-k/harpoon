#! /usr/bin/env python
from datetime import datetime

import pytz

from harpoon.commands.base import Command
from harpoon.lib.dnsdb import DnsDB, DNSDBError
from harpoon.lib.utils import ts_to_str, unbracket


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

    def run(self, args, plugins):
        dnsdb = DnsDB(self._config_data['Dnsdb']['key'])
        if 'subcommand' in args:
            if args.subcommand == "domain":
                try:
                    results = dnsdb.rrset_lookup(unbracket(args.DOMAIN))
                except DNSDBError as e:
                    print("Request failed : {}".format(e))
                else:
                    for r in results:
                        print("{}\t{}\t{}\t{}".format(
                            r['rrtype'],
                            ts_to_str(r['time_first']),
                            ts_to_str(r['time_last']),
                            "/ ".join(r['rdata'])
                        ))
            elif args.subcommand == "ip":
                try:
                    results = dnsdb.rdata_lookup(unbracket(args.IP), type="ip")
                except DNSDBError as e:
                    print("Request failed : {}".format(e))
                else:
                    if len(results) == 0:
                        print("No resuts for this IP")
                    for r in results:
                        print("{}\t{}\t{}\t{}".format(
                            r["rrtype"],
                            ts_to_str(r["time_first"]),
                            ts_to_str(r["time_last"]),
                            r["rrname"]
                        ))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data):
        if type == "domain":
            print("[+] Checking DNSdb...")
            dnsdb = DnsDB(self._config_data['Dnsdb']['key'])
            try:
                results = dnsdb.rrset_lookup(unbracket(query))
            except DNSDBError:
                print("Request failed")
                return
            for r in results:
                if r['rrtype'] in ['A', 'AAAA']:
                    for ip in r['rdata']:
                        data["passive_dns"].append({
                            "ip": ip.strip(),
                            "first": datetime.fromtimestamp(r['time_first']).astimezone(pytz.utc),
                            "last": datetime.fromtimestamp(r['time_last']).astimezone(pytz.utc),
                            "source": "DNSdb"
                        })
        elif type == "ip":
            print("[+] Checking DNSdb...")
            dnsdb = DnsDB(self._config_data['Dnsdb']['key'])
            try:
                results = dnsdb.rdata_lookup(unbracket(query), type="ip")
            except DNSDBError:
                print("Request to DNSDB failed")
                return
            for r in results:
                if r['rrtype'] in ['A', 'AAAA']:
                    data["passive_dns"].append({
                        "domain": r["rrname"].strip(),
                        "first": datetime.fromtimestamp(r['time_first']).astimezone(pytz.utc),
                        "last": datetime.fromtimestamp(r['time_last']).astimezone(pytz.utc),
                        "source": "DNSdb"
                    })
