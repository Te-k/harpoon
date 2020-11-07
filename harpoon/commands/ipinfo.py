#! /usr/bin/env python
import json
import os
import sys
import time

from harpoon.commands.base import Command
from harpoon.lib.ipinfo import IPInfo, IPInfoError
from harpoon.lib.utils import unbracket


class CommandIPInfo(Command):
    """
    # ipinfo.io plugin

    **Query ipinfo.io API**

    * Get info on an IP : `harpoon ipinfo ip IP`
    * Get infos on a list of IPs in a file : `harpoon ipinfo file FILE`
    """
    name = "ipinfo"
    description = "Request ipinfo.io information"
    config = {'IPInfo': ['token']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('ip', help='Information on an IP')
        parser_a.add_argument('IP', help='IP address')
        parser_a.set_defaults(subcommand='ip')
        parser_b = subparsers.add_parser('file', help='Information on a list of IPs')
        parser_b.add_argument('FILE', help='Filename')
        parser_b.add_argument('--delay', '-d', type=int, default=1, help='Delay between two queries in seconds')
        parser_b.set_defaults(subcommand='file')
        self.parser = parser

    def run(self, conf, args, plugins):
        ipinfo = IPInfo(token=conf['IPInfo']['token'])
        if 'subcommand' in args:
            if args.subcommand == 'ip':
                try:
                    infos = ipinfo.get_infos(unbracket(args.IP))
                except IPInfoError:
                    print("Invalid request")
                else:
                    print(json.dumps(infos,  sort_keys=True, indent=4, separators=(',', ': ')))
            elif args.subcommand == 'file':
                if os.path.isfile(args.FILE):
                    with open(args.FILE) as f:
                        data = f.read().split("\n")
                    print("IP;Hostname;City;Region;Country;Location;Company Name;Company Domain;Company Type;ASN;AS Name;AS Domain;AS Route;AS Type")
                    for d in data:
                        if d.strip() == '':
                            continue
                        ip = unbracket(d.strip())
                        try:
                            infos = ipinfo.get_infos(ip)
                        except IPInfoError:
                            print("%s;;;;;;;;;;;;;" % ip)
                        else:
                            if "company" in infos and "asn" in infos:
                                print("%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s" % (
                                        ip,
                                        infos['hostname'] if 'hostname' in infos else '',
                                        infos['city'] if 'city' in infos else '',
                                        infos['region'] if 'region' in infos else '',
                                        infos['country'] if 'country' in infos else '',
                                        infos['loc'] if 'loc' in infos else '',
                                        infos['company']['name'] if 'company' in infos else '',
                                        infos['company']['domain'] if 'company' in infos else '',
                                        infos['company']['type'] if 'company' in infos else '',
                                        infos['asn']['asn'] if 'asn' in infos['asn'] else '',
                                        infos['asn']['name'] if 'name' in infos['asn'] else '',
                                        infos['asn']['domain'] if 'domain' in infos['asn'] else '',
                                        infos['asn']['route'] if 'route' in infos['asn'] else '',
                                        infos['asn']['type'] if 'type' in infos['asn'] else ''
                                    )
                                )
                            elif "company" in infos and "asn" not in infos:
                                print("%s;%s;%s;%s;%s;%s;%s;%s;%s;;;;;" % (
                                        ip,
                                        infos['hostname'] if 'hostname' in infos else '',
                                        infos['city'],
                                        infos['region'],
                                        infos['country'],
                                        infos['loc'],
                                        infos['company']['name'],
                                        infos['company']['domain'],
                                        infos['company']['type']
                                    )
                                )
                            elif "asn" in infos and "company" not in infos:
                                print("%s;%s;%s;%s;%s;%s;;;;%s;%s;%s;%s;%s" % (
                                        ip,
                                        infos['hostname'] if 'hostname' in infos else '',
                                        infos['city'],
                                        infos['region'],
                                        infos['country'],
                                        infos['loc'],
                                        infos['asn']['asn'],
                                        infos['asn']['name'],
                                        infos['asn']['domain'],
                                        infos['asn']['route'],
                                        infos['asn']['type']
                                    )
                                )
                            else:
                                print("%s;%s;%s;%s;%s;%s;;;;%s;%s;;;" % (
                                        ip,
                                        infos['hostname'] if 'hostname' in infos else '',
                                        infos['city'],
                                        infos['region'],
                                        infos['country'],
                                        infos['loc'],
                                        infos['org'].split(' ')[0],
                                        ' '.join(infos['org'].split(" ")[1:])
                                    )
                                )
                        time.sleep(args.delay)

                else:
                    print("This file does not exist")
                    sys.exit(1)
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
