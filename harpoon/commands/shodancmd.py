#! /usr/bin/env python
import sys
import json
import shodan
from harpoon.commands.base import Command


class CommandShodan(Command):
    """
    # Shodan

    **Queries information from shodan.io API***

    * Get information on an IP : `harpoon shodan ip IP`
    * Get summary (only ports 22, 80 and 443) of historical data on an ip : `harpoon shodan ip -H -s IP`
    * Get raw json of historical data : `harpoon shodan ip -H -v IP`
    * Search in the database: `harpoon shodan search SEARCH`
    """
    name = "shodan"
    description = "Requests Shodan API"
    config = {'Shodan': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('ip', help='Get information on an IP address')
        parser_a.add_argument('IP', help='IP to be searched')
        parser_a.add_argument('--history', '-H', action='store_true',
                help='Also display historical information')
        parser_a.add_argument('-v', '--verbose', action='store_true',
                help="Verbose mode (display raw json)")
        parser_a.add_argument('-s', '--summary', action='store_true',
                help="Only display information for ports 22, 80 and 443")
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
                    res = api.host(args.IP, history=args.history)
                except shodan.exception.APIError:
                    print("IP not found in Shodan")
                else:
                    if args.verbose:
                        print(json.dumps(res, sort_keys=True, indent=4))
                    else:
                        if args.summary:
                            for d in res['data']:
                                if d['port'] == 22:
                                    print("%s - port 22 ssh - %s" % (
                                            d['timestamp'][:19],
                                            d['data'].split("\n")[0]
                                        )
                                    )
                                elif d['port'] == 80:
                                    print("%s - port 80 http - Server \"%s\"" % (
                                            d['timestamp'][:19],
                                            d['http']['server']
                                        )
                                    )
                                elif d['port'] == 443:
                                    if 'cert' in d['ssl']:
                                        print("%s - port 443 https - Cert \"%s\" \"%s\" %s - Server \"%s\"" % (
                                                d['timestamp'][:19],
                                                d['ssl']['cert']['subject']['CN'],
                                                d['ssl']['cert']['issuer']['CN'],
                                                d['ssl']['cert']['fingerprint']['sha1'],
                                                d['http']['server']
                                            )
                                        )
                                    else:
                                        print("%s - port 443 https - Cert Unknown- Server \"%s\"" % (
                                                d['timestamp'][:19],
                                                d['http']['server']
                                            )
                                        )
                        else:
                            for d in res['data']:
                                print(d['timestamp'])
                                print(d['_shodan']['module'])
                                print("%s/%i" % (d['transport'], d['port']))
                                print(d['data'])
                                if 'html' in d:
                                    print(d['html'])
                                if 'http' in d:
                                    print(json.dumps(d['http']))
                                print('')

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
