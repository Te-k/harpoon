#! /usr/bin/env python
import json
from harpoon.commands.base import Command
from harpoon.lib.hibp import HIBP, HibpNotFound


class CommandHibp(Command):
    """
    # Have I Been Pwned

    **Requests Have I Been Pwned API https://haveibeenpwned.com/**

    * Search for an email: `harpoon hibp admin@example.org`
    * Search for leaks in pasts: `harpoon bibp -p admin@example.org`
    * See raw JSON output: `harpoon hibp -j admin@example.org`
    """
    name = "hibp"
    description = "Request Have I Been Pwned API (https://haveibeenpwned.com/)"
    config = {'hibp': ['key']}

    def add_arguments(self, parser):
        parser.add_argument('EMAIL',  help='Email to check')
        parser.add_argument('--pastes', '-p', help='Check pastes instead of breaches', action='store_true')
        parser.add_argument('--json', '-j', action='store_true', help='Check pastes instead of breaches')
        self.parser = parser

    def run(self, conf, args, plugins):
        h = HIBP(conf['hibp']['key'])
        if args.pastes:
            try:
                res = h.get_pastes(args.EMAIL)
            except HibpNotFound:
                print("Account not found in the HIBP database")
            else:
                if args.json:
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    print("Account found in %i pastes:" % len(res))
                    for r in res:
                        print('[+] %s: %s %s "%s"' % (
                                r['Date'],
                                r['Source'],
                                r['Id'],
                                r['Title']
                            )
                        )
        else:
            try:
                res = h.get_breaches_account(args.EMAIL)
            except HibpNotFound:
                print("Account not found in the HIBP database")
            else:
                if args.json:
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    print("Account found in %i breaches\n" % len(res))
                    for r in res:
                        print("%s\n%s\n%s\n" % (
                                r['Name'],
                                r['BreachDate'],
                                r['Description']
                            )
                        )
