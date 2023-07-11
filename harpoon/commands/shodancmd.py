#! /usr/bin/env python
import json

import shodan
from dateutil.parser import parse

from harpoon.commands.base import Command, Subcommand
from harpoon.lib.utils import unbracket


class SubcommandIP(Subcommand):
    description = "Get information on an IP address"
    cmd = "ip"

    def add_arguments(self, parser):
        parser.add_argument('IP', help='IP to be searched')
        parser.add_argument(
            '--history', '-H', action='store_true',
            help='Also display historical information')
        parser.add_argument(
            '-v', '--verbose', action='store_true',
            help="Verbose mode (display raw json)")
        parser.add_argument(
            '-s', '--summary', action='store_true',
            help="Only display information for ports 22, 80 and 443")

    def run(self, args):
        api = shodan.Shodan(self._config_data['Shodan']['key'])
        try:
            self.data = api.host(args.IP, history=args.history)
        except shodan.exception.APIError:
            self.data = None

    def display(self, args):
        if self.data is None:
            print("IP not found in Shodan")
            return

        if args.verbose:
            print(json.dumps(self.data, indent=4))
        else:
            if args.summary:
                for d in self.data['data']:
                    if d['port'] == 22:
                        print("{} - port 22 ssh - {}".format(
                                d['timestamp'][:19],
                                d['data'].split("\n")[0]
                            )
                        )
                    elif d['port'] == 80:
                        print("{} - port 80 http - Server \"{}\"" .format(
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
                for d in self.data['data']:
                    print(d['timestamp'])
                    print(d['_shodan']['module'])
                    print("%s/%i" % (d['transport'], d['port']))
                    print(d['data'])
                    if 'html' in d:
                        print(d['html'][:2000])
                    if 'http' in d:
                        print(json.dumps(d['http'])[:3000])
                    print('')


class SubcommandSearch(Subcommand):
    description = "Search in shodan"
    cmd = "search"

    def add_arguments(self, parser):
        parser.add_argument('QUERY', help='Query')
        parser.add_argument(
            '-v', '--verbose', action='store_true',
            help="Verbose mode (display raw json)")

    def run(self, args):
        api = shodan.Shodan(self._config_data['Shodan']['key'])
        self.data = api.search(args.QUERY)

    def display(self, args):
        if args.verbose:
            print(json.dumps(self.data, indent=4))
        else:
            print('%i results' % self.data['total'])
            for r in self.data['matches']:
                print('[+] {} ({}): port {}/{} -> {}\n'.format(
                        r['ip_str'],
                        r['org'],
                        r['transport'],
                        r['port'],
                        r['data'][:1000]
                    )
                )


class SubcommandSsh(Subcommand):
    description = "Get history of ssh keys from Shodan historical data"
    cmd = "ssh"

    def add_arguments(self, parser):
        parser.add_argument('IP', help='IP address')

    def run(self, args):
        api = shodan.Shodan(self._config_data['Shodan']['key'])
        try:
            res = api.host(unbracket(args.IP), history=True)
        except shodan.exception.APIError as e:
            print(e)
            self.data = None
            return

        self.data = {}
        for event in res['data']:
            if event['_shodan']['module'] == 'ssh':
                if 'ssh' not in event:
                    continue
                fingerprint = event['ssh']['fingerprint']
                date = parse(event['timestamp'])
                if fingerprint not in self.data:
                    self.data[fingerprint] = {
                        'first': date,
                        'last': date,
                        'fingerprint': fingerprint
                    }
                else:
                    if self.data[fingerprint]['first'] > date:
                        self.data[fingerprint]['first'] = date
                    if self.data[fingerprint]['last'] < date:
                        self.data[fingerprint]['last'] = date

    def display(self, args):
        if self.data is None:
            print("IP not found in Shodan")
            return

        for val in sorted(self.data.values(), key=lambda x: x['first']):
            print('{} - {} -> {}'.format(
                val['fingerprint'],
                val['first'].strftime('%Y-%m-%d'),
                val['last'].strftime('%Y-%m-%d')
            ))


class SubcommandQuota(Subcommand):
    description = "Show Shodan account quota information"
    cmd = "quota"

    def run(self, args):
        api = shodan.Shodan(self._config_data['Shodan']['key'])
        self.data = api.info()

    def display(self, args):
        print(json.dumps(self.data, indent=4))


# ------------------------------------ Main Command ---------------------------
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

    def __init__(self, config):
        super().__init__(config=config)
        self.add_subcommand(SubcommandIP)
        self.add_subcommand(SubcommandSearch)
        self.add_subcommand(SubcommandSsh)
        self.add_subcommand(SubcommandQuota)

    def intel_ip(self, query, data):
        print("[+] Checking Shodan...")
        api = shodan.Shodan(self._config_data['Shodan']['key'])
        try:
            res = api.host(query)
        except shodan.exception.APIError:
            pass
        else:
            for p in res["ports"]:
                data["ports"].append({
                    "port": p,
                    "source": "Shodan",
                    "info": ""
                })
