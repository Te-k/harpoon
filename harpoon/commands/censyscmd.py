#! /usr/bin/env python
import sys
import json
import censys
from censys import ipv4, certificates, query
from harpoon.commands.base import Command


class CommandCensys(Command):
    """
    # Censys plugin

    **Query Censys.io API**

    * Query information on an IP: `harpoon censys ip 172.217.2.174`
    * Query a certificate: `harpoon censys certificate ID`
    """
    name = "censys"
    description = "Request information from Censys database (https://censys.io/)"
    config = {'Censys': ['id', 'secret']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('ip', help='Get information on an IP address')
        parser_a.add_argument('IP', help='IP to be searched')
        parser_a.add_argument('--search', '-s', action='store_true',
                help='Search for this value in IP infos')
        parser_a.set_defaults(subcommand='ip')
        parser_b = subparsers.add_parser('cert', help='Get information on a certificate')
        parser_b.add_argument('ID', help='ID of the certificate')
        parser_b.set_defaults(subcommand='cert')
        self.parser = parser

    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            if args.subcommand == 'ip':
                api = ipv4.CensysIPv4(conf['Censys']['id'], conf['Censys']['secret'])
                if args.search:
                    res = api.search(args.IP)
                    for r in res:
                        if len(r['ip']) > 11:
                            print("[+] %s\t[Location: %s] [Ports: %s]" % (
                                    r['ip'],
                                    r['location.country'],
                                    " ".join(r['protocols'])
                                )
                            )
                        else:
                            print("[+] %s\t\t[Location: %s] [Ports: %s]" % (
                                    r['ip'],
                                    r['location.country'],
                                    " ".join(r['protocols'])
                                )
                            )
                else:
                    try:
                        ip = api.view(args.IP)
                        print(json.dumps(ip, sort_keys=True, indent=4, separators=(',', ': ')))
                    except censys.base.CensysNotFoundException:
                        print('IP not found')
            elif args.subcommand == 'cert':
                c = certificates.CensysCertificates(conf['Censys']['id'], conf['Censys']['secret'])
                res = c.view(args.ID)
                print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': ')))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
