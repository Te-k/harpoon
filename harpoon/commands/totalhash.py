#! /usr/bin/env python
import sys
import json
import hashlib
from harpoon.commands.base import Command
from harpoon.lib.totalhash import TotalHash, TotalHashNotFound
from harpoon.lib.utils import json_serial


class CommandTotalHash(Command):
    """
    # Total Hash

    **Query Total hash API https://totalhash.cymru.com/**

    * Check API usage: `harpoon totalhash usage`
    * Search for a file `harpoon totalhash search mutex:ASPLOG`
    * Search with all results (/!\ earch 10 results is one query): `harpoon totalhash search -a mutex:ASPLOG`
    * Get a file analysis: `harpoon totalhash hash HASH`
    """
    name = "totalhash"
    description = "Request Total Hash API"
    config = {'TotalHash': ['key', 'user']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('hash', help='Request info on a hash')
        parser_a.add_argument('HASH', help='Hash')
        parser_a.set_defaults(subcommand='hash')
        parser_f = subparsers.add_parser('usage', help='Print information on TotalHash API usage')
        parser_f.set_defaults(subcommand='usage')
        parser_e = subparsers.add_parser('search', help='Search in Total Hash database')
        parser_e.add_argument('QUERY', help='query')
        parser_e.add_argument('--all', '-a', help='Query all results', action='store_true')
        parser_e.set_defaults(subcommand='search')
        self.parser = parser

    def run(self, conf, args, plugins):
        th = TotalHash(conf['TotalHash']['user'], conf['TotalHash']['key'])
        if 'subcommand' in args:
            if args.subcommand == 'usage':
                print(th.usage())
            elif args.subcommand == "search":
                if args.all:
                    res = th.search_all(args.QUERY)
                else:
                    res = th.search(args.QUERY)
                print('%i files found:\n' % res['total'])
                for r in res['results']:
                    print(r)
            elif args.subcommand == 'hash':
                try:
                    res = th.analysis(args.HASH)
                except TotalHashNotFound:
                    print("File not found")
                else:
                    print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
