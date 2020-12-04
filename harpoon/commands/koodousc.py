#! /usr/bin/env python
import sys
import json
from datetime import datetime
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket
from harpoon.lib.koodous import Koodous, KoodousError, KoodousNotFound


class CommandKoodous(Command):
    """
    # Koodous plugin

    Queries the Koodous API https://koodous.com/

    * get info on a hash : `harpoon koodous hash SHA256`
    * Download a file : `harpoon koodous dl SHA256`
    """
    name = "koodous"
    description = "Request Koodous API"
    config = {'Koodous': ['token']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('hash', help='Get info on a SHA256 hash')
        parser_a.add_argument('HASH', help='SHA256 hash')
        parser_a.set_defaults(subcommand='hash')
        parser_b = subparsers.add_parser('search', help='Search in Koodous')
        parser_b.add_argument('QUERY', help='Query')
        parser_b.set_defaults(subcommand='search')
        parser_c = subparsers.add_parser('dl', help='Download a sample from Koodous')
        parser_c.add_argument('HASH', help='Sha256')
        parser_c.set_defaults(subcommand='dl')
        parser_d = subparsers.add_parser('analysis', help='Get a full analysis from Koodous')
        parser_d.add_argument('HASH', help='Sha256')
        parser_d.set_defaults(subcommand='analysis')
        self.parser = parser

    def run(self, conf, args, plugins):
        kd = Koodous(token=conf['Koodous']['token'])
        if 'subcommand' in args:
            try:
                if args.subcommand == "hash":
                    res = kd.sha256(args.HASH)
                    print(json.dumps(res, sort_keys=True, indent=4))
                elif args.subcommand == "search":
                    res = kd.search(args.QUERY)
                    print(json.dumps(res, sort_keys=True, indent=4))
                elif args.subcommand == "dl":
                    data = kd.download(args.HASH)
                    with open(args.HASH, "wb+") as f:
                        f.write(data)
                    print("File downlaoded as {}".format(args.HASH))
                elif args.subcommand == "analysis":
                    res = kd.analysis(args.HASH)
                    print(json.dumps(res, sort_keys=True, indent=4))
                else:
                    self.parser.print_help()
            except KoodousNotFound:
                print("Not found")
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        if type == "hash":
            if len(query) == 64:
                try:
                    kd = Koodous(token=conf['Koodous']['token'])
                    res = kd.sha256(query)
                except KoodousError:
                    pass
                else:
                    data["samples"].append({
                        "source": "Koodous",
                        "date": datetime.fromtimestamp(res["created_on"]),
                        "url": "https://koodous.com/apks/" + query
                    })
