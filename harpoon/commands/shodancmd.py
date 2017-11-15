#! /usr/bin/env python
import sys
import json
import shodan
from harpoon.commands.base import Command


class CommandShodan(Command):
    name = "shodan"
    description = "Requests Shodan API"
    config = {'Shodan': ['key']}

    def add_arguments(self, parser):
        parser.add_argument('--ip', '-i', help='Check IP of an host')
        parser.add_argument('--search', '-s', help='Search in shodan')
        self.parser = parser

    def run(self, conf, args):
        if 'Shodan' not in conf and 'key' not in conf['Shodan']:
            print('Bad configuration for Shodan, quitting...')
            sys.exit(1)
        api = shodan.Shodan(conf['Shodan']['key'])
        if args.ip:
            res = api.host(args.ip)
            print(json.dumps(res, sort_keys=True, indent=4))
        elif args.search:
            res = api.search(args.search)
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
