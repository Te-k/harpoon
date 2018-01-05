#! /usr/bin/env python
import sys
from harpoon.commands.base import Command
from harpoon.lib.pgp import Pgp


class CommandPgp(Command):
    """
    # PGP

    **Searches for PGP keys in MIT key servers**

    Example:
    ```
    harpoon pgp search lemonde.fr
    [+] 0x07A0514E0F568618	2017-12-19	Anne Michel anne.michel@lemonde.fr
    [+] 0xAE95106F1B5A0D7E	2017-11-28	perso maxime.loliee@gmail.com
					loliee maxime.loliee@gmail.com
					pro maxime@siliadev.com
					lemonde loliee@lemonde.fr
    [SNIP]
    ```

    Option `-o` just print the list of emails (no information on keys)
    """
    name = "pgp"
    description = "Search for information in PGP key servers"
    config = {}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommands')
        parser_a = subparsers.add_parser('search', help='Search in PGP server')
        parser_a.add_argument('SEARCH', help='Query')
        parser_a.add_argument('--only-emails', '-o', action='store_true',
                            help='Print only email addresses')
        parser_a.set_defaults(subcommand='search')
        self.parser = parser

    def run(self, conf, args, plugins):
        if hasattr(args, 'subcommand'):
            if args.subcommand == "search":
                res = Pgp.search(args.SEARCH)
                if len(res):
                    if args.only_emails:
                        emails = set()
                        for r in res:
                            for e in r['emails']:
                                if args.SEARCH.lower() in e[1].lower():
                                    emails.add(e[1])
                        for e in emails:
                            print(e)
                    else:
                        for r in res:
                            print("[+] %s\t%s\t%s %s" % (
                                    r['id'],
                                    r['date'].strftime("%Y-%m-%d"),
                                    r['emails'][0][0],
                                    r['emails'][0][1]
                                )
                            )
                            if len(r['emails']) > 1:
                                for e in r['emails'][1:]:
                                    print("\t\t\t\t\t%s %s" % (e[0], e[1]))
                else:
                    print("No results (could be too many results)")
                    print("Double check at http://pgp.mit.edu/pks/lookup?search=%s" % args.SEARCH)
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
