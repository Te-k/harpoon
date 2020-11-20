#! /usr/bin/env python
import sys
import json
import hashlib
from harpoon.commands.base import Command
from harpoon.lib.malshare import MalShare, MalShareFailed, MalShareNotFound, MalShareSampleMissing
from harpoon.lib.utils import json_serial


class CommandMalShare(Command):
    """
    # MalShare

    **Requests information from MalShare (https://malshare.com/)**

    * `harpoon malshare search beget.tech` : Search in the database
    * `harpoon malshare hash 924c1fb188fb8dcbcee616308389fc22` : Information about a hash
    * `harpoon  malshare download dde72ae232dc63298465861482d7bb93 -o infected` : ;Download the sample
    """
    name = "malshare"
    description = "Requests MalShare database"
    config = {'MalShare': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('hash', help='Request info on a hash')
        parser_a.add_argument('HASH', help='Hash')
        parser_a.set_defaults(subcommand='hash')
        parser_b = subparsers.add_parser('download', help='Download the given hash')
        parser_b.add_argument('HASH', help='Hash')
        parser_b.add_argument('--output', '-o', help='Output file name')
        parser_b.set_defaults(subcommand='download')
        parser_e = subparsers.add_parser('search', help='Search in MalShare database')
        parser_e.add_argument('QUERY', help='query')
        parser_e.set_defaults(subcommand='search')
        self.parser = parser

    def run(self, conf, args, plugins):
        ms = MalShare(conf['MalShare']['key'])
        if 'subcommand' in args:
            if args.subcommand == "search":
                try:
                    res = ms.search(args.QUERY)
                except MalShareFailed:
                    print("File not found")
                else:
                    print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))
            elif args.subcommand == 'hash':
                try:
                    res = ms.file_info(args.HASH)
                except MalShareNotFound:
                    print("File not found")
                else:
                    print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))
            elif args.subcommand == 'download':
                try:
                    data = ms.download(args.HASH)
                except MalShareNotFound:
                    print("File not found")
                except MalShareSampleMissing:
                    print("Missing sample, it is a bug")
                else:
                    outfile = args.output if args.output else args.HASH
                    with open(outfile, "w") as f:
                        f.write(data)
                    print("Sample created %s" % outfile)
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        if type == "hash":
            ms = MalShare(conf['MalShare']['key'])
            try:
                res = ms.file_info(query)
            except MalShareNotFound:
                pass
            else:
                data["samples"].append({
                    "date": None,
                    "source": "MalShare",
                    "url": "https://malshare.com/sample.php?action=detail&hash={}".format(query)
                })
