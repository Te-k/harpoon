#! /usr/bin/env python
import sys
import json
import requests
from harpoon.commands.base import Command


class CommandQuad9(Command):
    """
    # Quad9

    Check if a domain is blocked by Quad9 https://quad9.net/

    `harpoon quad9 DOMAIN`
    """
    name = "quad9"
    description = "Check if a domain is blocked by Quad9"

    def add_arguments(self, parser):
        parser.add_argument('DOMAIN',  help='Domain to be checked')
        parser.add_argument('--type', '-t', default='A',  help='DNS Type')
        parser.add_argument('--verbose', '-v', action='store_true',  help='Display results')
        self.parser = parser

    def run(self, conf, args, plugins):
        params = {
            'name': args.DOMAIN,
            'type': args.type,
            'ct': 'application/dns-json',
        }
        r = requests.get("https://dns.quad9.net:5053/dns-query", params=params)
        if r.status_code != 200:
            print('Problem querying quad9 :(')
            sys.exit(1)
        if r.json()['Status'] == 3:
            print("{} - BLOCKED".format(args.DOMAIN))
        else:
            print("{} - NOT BLOCKED".format(args.DOMAIN))
        if args.verbose:
            print(json.dumps(r.json(), indent=4))
