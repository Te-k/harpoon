#! /usr/bin/env python
import json
import pytz
from dateutil.parser import parse
from harpoon.lib.utils import unbracket
from harpoon.commands.base import Command
from pybinaryedge import BinaryEdge, BinaryEdgeException, BinaryEdgeNotFound


class CommandBinaryEdge(Command):
    """
    # binaryedge plugin

    **Query the BinaryEdge API https://www.binaryedge.io/**

    * Check details on an IP: `harpoon binaryedge ip IP`
    * Search for a specific query: `harpoon binaryedge search QUERY`
    """
    name = "binaryedge"
    description = "Request BinaryEdge API"
    config = {'BinaryEdge': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Commands')
        parser_a = subparsers.add_parser('config', help='Configure pybinary edge')
        parser_a.add_argument('--key', '-k', help='Configure the API key')
        parser_a.set_defaults(which='config')
        parser_b = subparsers.add_parser('ip', help='Query an IP address')
        parser_b.add_argument('IP', help='IP to be requested')
        parser_b.add_argument(
            '--historical', '-H', action='store_true',
            help='Requests historical data about an IP'
        )
        parser_b.add_argument(
            '--score', '-s', action='store_true',
            help='Requests vulnerability score about an IP'
        )
        parser_b.add_argument(
            '--image', '-i', action='store_true',
            help='Requests images identified for an IP'
        )
        parser_b.add_argument(
            '--torrent', '-t', action='store_true',
            help='Request torrents identified for an IP'
        )
        parser_b.add_argument(
            '--dns', '-d', action='store_true',
            help='Requests images identified for an IP'
        )
        parser_b.add_argument('--page', '-p', type=int, default=1,
            help='Get specific page')
        parser_b.set_defaults(which='ip')
        parser_c = subparsers.add_parser('search', help='Search in the database')
        parser_c.add_argument('SEARCH', help='Search request')
        parser_c.add_argument(
            '--page', '-p', type=int, default=1,
            help='Get specific page'
        )
        parser_c.add_argument(
            '--image', '-i', action='store_true',
            help='Requests images identified for an IP'
        )
        parser_c.set_defaults(which='search')
        parser_d = subparsers.add_parser('dataleaks', help='Search in the leaks database')
        parser_d.add_argument('EMAIL', help='Search email in the leaks database')
        parser_d.add_argument(
            '--domain', '-d', action='store_true',
            help='Search for domain instead of email'
        )
        parser_d.set_defaults(which='dataleaks')
        parser_e = subparsers.add_parser('domain', help='Search information on a domain')
        parser_e.add_argument('DOMAIN', help='Domain to be requested')
        parser_e.add_argument('--page', '-p', type=int, default=1,
                help='Get specific page')
        parser_e.add_argument(
            '--subdomains', '-s', action='store_true',
            help='Returns subdomains'
        )
        parser_e.set_defaults(which='domain')
        self.parser = parser

    def run(self, conf, args, plugins):
        be = BinaryEdge(conf['BinaryEdge']['key'])
        try:
            if hasattr(args, 'which'):
                if args.which == 'ip':
                    if args.score:
                        res = be.host_score(unbracket(args.IP))
                    elif args.image:
                        res = be.image_ip(unbracket(args.IP))
                    elif args.torrent:
                        if args.historical:
                            res = be.torrent_historical_ip(unbracket(args.IP))
                        else:
                            res = be.torrent_ip(unbracket(args.IP))
                    elif args.historical:
                        res = be.host_historical(unbracket(args.IP))
                    elif args.dns:
                        res = be.domain_ip(args.IP, page=args.page)
                    else:
                        res = be.host(unbracket(args.IP))
                    print(json.dumps(res, sort_keys=True, indent=4))
                elif args.which == 'search':
                    if args.image:
                        res = be.image_search(args.SEARCH, page=args.page)
                    else:
                        res = be.host_search(args.SEARCH, page=args.page)
                    print(json.dumps(res, sort_keys=True, indent=4))
                elif args.which == 'dataleaks':
                    if args.domain:
                        res = be.dataleaks_organization(args.EMAIL)
                    else:
                        res = be.dataleaks_email(args.EMAIL)
                    print(json.dumps(res, sort_keys=True, indent=4))
                elif args.which == 'domain':
                    if args.subdomains:
                        res = be.domain_subdomains(args.DOMAIN, page=args.page)
                    else:
                        res = be.domain_dns(args.DOMAIN, page=args.page)
                    print(json.dumps(res, sort_keys=True, indent=4))
                else:
                    self.parser.print_help()
            else:
                self.parser.print_help()
        except ValueError as e:
            print('Invalid Value: %s' % e.message)
        except BinaryEdgeNotFound:
            print('Search term not found')
        except BinaryEdgeException as e:
            print('Error: %s' % e.message)

    def intel(self, type, query, data, conf):
        if type == "domain":
            print("[+] Downloading BinaryEdge information....")
            try:
                be = BinaryEdge(conf["BinaryEdge"]["key"])
                res = be.domain_dns(query)
                for d in res["events"]:
                    if "A" in d:
                        for a in d["A"]:
                            data["passive_dns"].append(
                                {
                                    "ip": a,
                                    "first": parse(d["updated_at"]).astimezone(pytz.utc),
                                    "last": parse(d["updated_at"]).astimezone(pytz.utc),
                                    "source": "BinaryEdge",
                                }
                            )
            except BinaryEdgeException:
                print(
                    "You need a paid BinaryEdge subscription for this request"
                )
        elif type == "ip":
            print("[+] Downloading BinaryEdge information....")
            try:
                be = BinaryEdge(conf["BinaryEdge"]["key"])
                res = be.domain_ip(query)
                for d in res["events"]:
                    data["passive_dns"].append(
                        {
                            "domain": d["domain"],
                            "first": parse(d["updated_at"]).astimezone(pytz.utc),
                            "last": "",
                            "source": "BinaryEdge",
                        }
                    )
                res = be.host(query)
                for d in res["events"]:
                    data["ports"].append({
                        "port": d["port"],
                        "info": "",
                        "source": "BinaryEdge"
                    })
            except BinaryEdgeException:
                print(
                    "You need a paid BinaryEdge subscription for this request"
                )


