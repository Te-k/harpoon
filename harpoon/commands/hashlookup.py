#! /usr/bin/env python
import json
from datetime import datetime

from pyhashlookup.api import Hashlookup, PyHashlookupError

from harpoon.commands.base import Command


class CommandHashLookup(Command):
    """
    # CIRCL Hash Lookup

    **Search a hash in CIRCL Hash lookup base**
    https://circl.lu/services/hashlookup/

    * `harpoon hashlookup hash 8ED4B4ED952526D89899E723F3488DE4`
    """
    name = "hashlookup"
    description = "Request CIRCL Hash Lookup db"
    config = {"HashLookup": []}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('hash', help='Request info on a hash')
        parser_a.add_argument('HASH', help='Hash')
        parser_a.set_defaults(subcommand='hash')
        parser_b = subparsers.add_parser('info', help='Info about the db')
        parser_b.set_defaults(subcommand='info')
        # TODO: bulk query
        self.parser = parser

    def run(self, args, plugins):
        hl = Hashlookup()
        if 'subcommand' in args:
            if args.subcommand == "info":
                print(json.dumps(hl.info(), indent=4))
            elif args.subcommand == 'hash':
                try:
                    res = hl.lookup(args.HASH)
                except PyHashlookupError:
                    print("Invalid Hash format")
                else:
                    print(json.dumps(res, indent=4))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel_hash(self, query, data):
        print("[+] Checking CIRCL Hash Lookup...")
        hl = Hashlookup()
        try:
            res = hl.lookup(query)
        except PyHashlookupError:
            print("Invalid Hash format")
        else:
            if "FileName" in res:
                # File exist
                data["reports"].append({
                    "title": "Hash found in CIRCL db: {}".format(res["FileName"]),
                    "source": res["source"],
                    "date": datetime.fromtimestamp(float(res["insert-timestamp"])),
                    "url": ""
                })
