#! /usr/bin/env python
import json
import time

import censys
from censys.search import CensysCerts, CensysHosts

from harpoon.commands.base import Command
from harpoon.lib.utils import unbracket


class CommandCensys(Command):
    """
    # Censys plugin

    **Query Censys.io API**

    * Query information on an IP: `harpoon censys ip 172.217.2.174`
    * Query a certificate: `harpoon censys certificate ID`
    * Search for hosts: `harpoon censys search QUERY -p 20`
    """
    name = "censys"
    description = "Request information from Censys database (https://censys.io/)"
    config = {'Censys': ['id', 'secret']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser(
            'ip', help='Get information on an IP address')
        parser_a.add_argument('IP', help='IP to be searched')
        parser_a.add_argument('--events', '-e', action='store_true',
                              help='Show events for this IP')
        parser_a.set_defaults(subcommand='ip')
        parser_b = subparsers.add_parser(
            'cert', help='Get information on a certificate')
        parser_b.add_argument('ID', help='ID of the certificate')
        parser_b.set_defaults(subcommand='cert')
        parser_e = subparsers.add_parser(
            'search', help='Search for hosts using Censys V2 syntax')
        parser_e.add_argument('QUERY', help='Censys v2 query')
        parser_e.add_argument('--pages', '-p', default=10, type=int,
                              help='Number of pages (100 results per page, each page costs 1 quota)')
        parser_e.add_argument('--verbose', '-v', action='store_true',
                              help='Verbose mode (display more than just the IP address)')
        parser_e.add_argument(
            '--file', '-f', action='store_true', help='Read the query from a file')
        parser_e.add_argument(
            '--output', '-o', help='Output file (stdout if not provided)')
        parser_e.set_defaults(subcommand='search')
        self.parser = parser

    def run(self, args, plugins):
        if 'subcommand' in args:
            if args.subcommand == 'ip':
                api = CensysHosts(
                    self._config_data['Censys']['id'],
                    self._config_data['Censys']['secret'])
                if args.events:
                    res = api.view_host_events(unbracket(args.IP))
                    print(json.dumps(res,
                          indent=4, separators=(',', ': ')))
                else:
                    try:
                        ip = api.view(unbracket(args.IP))
                        print(json.dumps(ip, indent=4, separators=(',', ': ')))
                    except censys.base.CensysNotFoundException:
                        print('IP not found')
            elif args.subcommand == 'cert':
                try:
                    print(
                        "Viewing certs is not implemented yet, seeing hosts for this cert:")
                    c = CensysCerts(
                        self._config_data['Censys']['id'],
                        self._config_data['Censys']['secret'])
                    res = c.get_hosts_by_cert(args.ID)
                except censys.base.CensysNotFoundException:
                    print("Certificate not found")
                else:
                    print(json.dumps(res, sort_keys=True,
                          indent=4, separators=(',', ': ')))
            elif args.subcommand == 'search':
                api = CensysHosts(
                    self._config_data['Censys']['id'],
                    self._config_data['Censys']['secret'])
                if args.file:
                    with open(args.QUERY) as f:
                        query = f.read().strip()
                else:
                    query = args.QUERY
                print("Searching for {}".format(query))
                if args.output:
                    fout = open(args.output, "w+")
                    total = 0
                for page in api.search(query, per_page=100, pages=args.pages):
                    if args.output:
                        for host in page:
                            if args.verbose:
                                fout.write("{},{},{},{}\n".format(
                                    host["ip"],
                                    host["location"]["country"],
                                    host["autonomous_system"]["asn"],
                                    host["autonomous_system"]["name"]
                                ))
                            else:
                                fout.write("{}\n".format(host["ip"]))
                        total += len(page)
                        print("{} ips written in {}".format(
                            total,
                            args.output
                        ))
                    else:
                        for host in page:
                            if args.verbose:
                                try:
                                    print("{} - [{}] - [{}]".format(
                                        host["ip"],
                                        ", ".join(
                                            [str(a["port"]) + "/" + a["service_name"] for a in host["services"]]),
                                        host["autonomous_system"]["asn"] +
                                        " / " +
                                        host["autonomous_system"]["name"]
                                    ))
                                except KeyError:
                                    print(host["ip"])
                            else:
                                print(host["ip"])
                    # To avoid rate limiting
                    time.sleep(0.5)
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data):
        if type == "ip":
            print("[+] Checking Censys...")
            api = CensysHosts(
                self._config_data['Censys']['id'],
                self._config_data['Censys']['secret'])
            ip = api.view(query)
            for service in ip["services"]:
                data["ports"].append({
                    "port": service["port"],
                    "info": service["service_name"],
                    "source": "Censys"
                })

    def get_subdomains(self, conf, query, verbose):
        api = CensysHosts(
            self._config_data['Censys']['id'],
            self._config_data['Censys']['secret'])
        raw = api.search(query)
        cleaned = raw.view_all()
        for host in cleaned:
            for i in cleaned[host]['services']:
                try:
                    leaf_data = i['tls']['certificates']['leaf_data']['names']
                except KeyError:
                    pass

        return leaf_data
