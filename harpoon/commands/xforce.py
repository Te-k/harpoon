#! /usr/bin/env python
import json
import requests
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket, is_ip
from harpoon.lib.xforce import XforceExchange, XforceExchangeFailed, XforceExchangeNotFound


class CommandXforce(Command):
    """
    # IBM Xforce Exchange

    Query IBM Xforce Exchange API
    """
    name = "xforce"
    description = "Query IBM Xforce Exchange API"
    config = {'Xforce': ['key', 'password']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('ip_reputation', help='Get IP Reputation')
        parser_a.add_argument('IP',  help='IP address')
        parser_a.set_defaults(subcommand='ip_reputation')
        parser_b = subparsers.add_parser('ip', help='Get information on an IP')
        parser_b.add_argument('IP',  help='IP address')
        parser_b.set_defaults(subcommand='ip')
        parser_c = subparsers.add_parser('ip_malware', help='Returns the malware associated with the entered IP.')
        parser_c.add_argument('IP',  help='IP address')
        parser_c.set_defaults(subcommand='ip_malware')
        parser_d = subparsers.add_parser('search', help='Returns a list of public Collections that were found')
        parser_d.add_argument('QUERY',  help='Query')
        parser_d.set_defaults(subcommand='search')
        parser_e = subparsers.add_parser('dns', help='Returns live and passive DNS records.')
        parser_e.add_argument('INPUT',  help='Input')
        parser_e.set_defaults(subcommand='dns')
        parser_f = subparsers.add_parser('casefile', help='Returns a JSON resentation of a Collection')
        parser_f.add_argument('ID',  help='ID of a casefile')
        parser_f.set_defaults(subcommand='casefile')
        parser_g = subparsers.add_parser('malware', help='Returns a malware report for the given file hash, For example, md5, sha1 and sha256.')
        parser_g.add_argument('HASH',  help='Hash of a malware')
        parser_g.set_defaults(subcommand='malware')
        parser_h = subparsers.add_parser('url', help='Returns the URL report for the entered URL.')
        parser_h.add_argument('URL',  help='Url')
        parser_h.set_defaults(subcommand='url')
        parser_i = subparsers.add_parser('usage', help='Get API usage details')
        parser_i.set_defaults(subcommand='usage')
        parser_j = subparsers.add_parser('whois', help='Returns whois information on a domain')
        parser_j.add_argument('DOMAIN',  help='Domain')
        parser_j.set_defaults(subcommand='whois')
        self.parser = parser

    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            xe = XforceExchange(conf['Xforce']['key'], conf['Xforce']['password'])
            if args.subcommand == "ip_reputation":
                res = xe.ip_reputation(unbracket(args.IP))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif args.subcommand == 'ip':
                res = xe.ip(unbracket(args.IP))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif args.subcommand == 'ip_malware':
                res = xe.ip_malware(unbracket(args.IP))
                print(json.dumps(res, sort_keys=False, indent=4))
            elif args.subcommand == 'search':
                res = xe.search(args.QUERY)
                print(json.dumps(res, sort_keys=False, indent=4))
            elif args.subcommand == 'dns':
                res = xe.dns(args.INPUT)
                print(json.dumps(res, sort_keys=False, indent=4))
            elif args.subcommand == 'casefile':
                res = xe.casefile(args.ID)
                print(json.dumps(res, sort_keys=False, indent=4))
            elif args.subcommand == 'malware':
                try:
                    res = xe.malware(args.HASH)
                    print(json.dumps(res, sort_keys=False, indent=4))
                except XforceExchangeNotFound:
                    print("Not found")
            elif args.subcommand == 'url':
                res = xe.url(args.URL)
                print(json.dumps(res, sort_keys=False, indent=4))
            elif args.subcommand == 'usage':
                res = xe.usage()
                print(json.dumps(res, sort_keys=False, indent=4))
            elif args.subcommand == 'whois':
                res = xe.whois(unbracket(args.DOMAIN))
                print(json.dumps(res, sort_keys=False, indent=4))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
