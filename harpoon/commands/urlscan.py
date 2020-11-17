#! /usr/bin/env python
import sys
import json
import requests
import pytz
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.urlscan import UrlScan


class CommandUrlscan(Command):
    """
    # url scan

    Allows to search and scan urls using https://urlscan.io/

    * Query the database : `harpoon urlscan search DOMAIN`
    * View an analysis : `harpoon urlscan view UID`
    """
    name = "urlscan"
    description = "Search and submit urls to urlscan.io"
    config = {'UrlScan': []}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('search', help='Search in urlscan')
        parser_a.add_argument('QUERY', help='DOMAIN to be queried')
        parser_a.add_argument('--raw', '-r', action='store_true', help='Shows raw results')
        parser_a.set_defaults(subcommand='search')
        parser_c = subparsers.add_parser('view', help='View urlscan analysis')
        parser_c.add_argument('UID', help='UId of the analysis')
        parser_c.set_defaults(subcommand='view')
        self.parser = parser

    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            us = UrlScan()
            if args.subcommand == 'search':
                # Search
                res = us.search(args.QUERY)
                if args.raw:
                    print(json.dumps(res, sort_keys=True, indent=4))
                else:
                    if len(res['results']) > 0:
                        for r in res['results']:
                            print("{} - {} - {} - https://urlscan.io/result/{}".format(
                                r["task"]["time"],
                                r["page"]["url"],
                                r["page"]["ip"] if "ip" in r["page"] else "",
                                r["_id"]
                                )
                            )
                    else:
                        print("No results for this query")
            elif args.subcommand == 'view':
                print(json.dumps(us.view(args.UID), sort_keys=True, indent=4))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        if type in ["domain", "ip"]:
            print('[+] Checking UrlScan...')
            us = UrlScan()
            res = us.search(query)
            if 'results' in res:
                for r in res['results']:
                    data["urls"].append({
                        "date": parse(r["task"]["time"]).astimezone(pytz.utc),
                        "url": r["page"]["url"],
                        "ip": r["page"]["ip"] if "ip" in r["page"] else "",
                        "source": "UrlScan"
                    })

