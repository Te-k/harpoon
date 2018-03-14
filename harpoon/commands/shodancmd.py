#! /usr/bin/env python
import sys
import json
import shodan
from harpoon.commands.base import Command


class CommandShodan(Command):
    """
    # Shodan

    **Queries information from shodan.io API***

    * Get information on an IP (JSON output): `harpoon -i IP`
    * Search in the database: `harpoon -s SEARCH`
    """
    name = "shodan"
    description = "Requests Shodan API"
    config = {'Shodan': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('ip', help='Get information on an IP address')
        parser_a.add_argument('IP', help='IP to be searched')
        parser_a.set_defaults(subcommand='ip')
        parser_b = subparsers.add_parser('search', help='Search in shodan')
        parser_b.add_argument('QUERY', help='Query')
        parser_b.set_defaults(subcommand='search')
        self.parser = parser

    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            if 'Shodan' not in conf and 'key' not in conf['Shodan']:
                print('Bad configuration for Shodan, quitting...')
                sys.exit(1)
            api = shodan.Shodan(conf['Shodan']['key'])
            if args.subcommand == 'ip':
                try:
                    res = api.host(args.IP)
                except shodan.exception.APIError:
                    print("IP not found in Shodan")
                else:
                    print(json.dumps(res, sort_keys=True, indent=4))
            elif args.subcommand == 'search':
                res = api.search(args.QUERY)
                print('%i results' % res['total'])
                for r in res['matches']:
                    print('[+] %s (%s): port %s/%i -> %s\n' % (
                            r['ip_str'],
                            r['org'],
                            r['transport'],
                            r['port'],
                            r['data'][:1000]
                        )
                    )
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
