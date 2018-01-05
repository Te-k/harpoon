#! /usr/bin/env python
import sys
import json
from harpoon.commands.base import Command
from pyhunter import PyHunter

class CommandHunter(Command):
    """
    # Hunter.io

    **Requests Hunter.io plugin https://hunter.io/**

    * Search for an email: `harpoon hunter email FIRSTNAME LASTNAME DOMAIN`
    * Search for a domain: `harpoon hunder domain example.org`
    """
    name = "hunter"
    description = "Request hunter.io information through the API"
    config = { 'Hunter': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('email')
        parser_a.add_argument('NAME', help='Name of the user')
        parser_a.add_argument('DOMAIN', help='Domain of the user')
        parser_a.set_defaults(subcommand='email')
        parser_a = subparsers.add_parser('domain')
        parser_a.add_argument('DOMAIN', help='Domain to look for')
        parser_a.set_defaults(subcommand='domain')
        self.parser = parser

    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            hunter = PyHunter(conf['Hunter']['key'])
            if args.subcommand == 'email':
                if ' ' not in args.NAME:
                    print('Name should contains first and last name')
                    print('(Yes this API is useless)')
                    sys.exit(1)
                res = hunter.email_finder(
                    domain=args.DOMAIN,
                    full_name=args.NAME,
                    raw=True
                )
                print(json.dumps(res, sort_keys=True, indent=4))
            elif args.subcommand == 'domain':
                res = hunter.domain_search(args.DOMAIN)
                print(json.dumps(res, sort_keys=True, indent=4))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
