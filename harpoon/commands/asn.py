#! /usr/bin/env python
import sys
import json
import requests
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket

class CommandAsn(Command):
    name = "asn"
    description = "Gather information on an ASN"
    config = None

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('info', help='Information on an ASn number')
        parser_a.add_argument('ASN', help='ASN Number')
        parser_a.add_argument('--json', '-j', help='Show raw json', action='store_true')
        parser_a.set_defaults(subcommand='info')
        self.parser = parser

    def run(self, conf, args, plugins):
        if args.ASN.lower().startswith("asn"):
            asn = int(args.ASN[3:])
        elif args.ASN.lower().startswith("as"):
            asn = int(args.ASN[2:])
        else:
            asn = int(args.ASN)
        if 'subcommand' in args:
            if args.subcommand == 'info':
                r = requests.get('https://peeringdb.com/api/net?asn=%i' % asn)
                if r.status_code == 200:
                    if args.json:
                        print(json.dumps(r.json(), sort_keys=False, indent=4))
                    else:
                        data = r.json()['data'][0]
                        print('Name: %s' % data['name'])
                        if data['aka'] != '':
                            print("aka: %s" % data['aka'])
                        if data['notes'] != '':
                            print("Notes: %s" % data['notes'])
                        if data['website'] != '':
                            print("Website: %s" % data['website'])
                        print("Created: %s" % data['created'])
                else:
                    print("ASN not found")

            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
