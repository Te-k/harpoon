#! /usr/bin/env python
import json
import time

import pytz
from dateutil.parser import parse

from harpoon.commands.base import Command
from harpoon.lib.urlscan import UrlScan, UrlScanError, UrlScanQuotaExceeded


class CommandUrlscan(Command):
    """
    # url scan

    Allows to search and scan urls using https://urlscan.io/

    * Query the database : `harpoon urlscan search DOMAIN`
    * View an analysis : `harpoon urlscan view UID`
    """
    name = "urlscan"
    description = "Search and submit urls to urlscan.io"
    # Key is optional
    config = {'UrlScan': []}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('search', help='Search in urlscan')
        parser_a.add_argument('QUERY', help='DOMAIN to be queried')
        parser_a.add_argument('--raw', '-r', action='store_true', help='Shows raw results')
        parser_a.set_defaults(subcommand='search')
        parser_b = subparsers.add_parser('list', help='Search list of domains or IPs in urlscan')
        parser_b.add_argument('FILE', help='File containing IPs or domains')
        parser_b.set_defaults(subcommand='list')
        parser_c = subparsers.add_parser('view', help='View urlscan analysis')
        parser_c.add_argument('UID', help='UId of the analysis')
        parser_c.set_defaults(subcommand='view')
        parser_d = subparsers.add_parser('quota', help='Show quota')
        parser_d.set_defaults(subcommand='quota')
        self.parser = parser

    def run(self, args, plugins):
        if 'subcommand' in args:
            # Optional key
            try:
                key = self._config_data['UrlScan']['key']
                if key.strip() != "":
                    us = UrlScan(key)
                else:
                    us = UrlScan()
            except KeyError:
                us = UrlScan()
            if args.subcommand == 'search':
                # Search
                try:
                    res = us.search(args.QUERY)
                except UrlScanError as e:
                    print("Error: {}".format(e.message))
                else:
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
                try:
                    print(json.dumps(us.view(args.UID), sort_keys=True, indent=4))
                except UrlScanError as e:
                    print("Error: {}".format(e.message))
            elif args.subcommand == 'list':
                with open(args.FILE) as f:
                    data = f.read().split('\n')
                for d in data:
                    d = d.strip()
                    if d == "":
                        continue
                    print("##### {}".format(d))
                    try:
                        res = us.search(d)
                    except UrlScanQuotaExceeded as e:
                        duration = int(e.message[-13:-9]) + 10
                        print("Out of quota, waiting for {} seconds".format(duration))
                        time.sleep(duration)
                        res = us.search(d)
                    if 'results' in res:
                        if len(res['results']) > 0:
                            for r in res['results']:
                                print("{} - {} - {} - https://urlscan.io/result/{}".format(
                                    r["task"]["time"],
                                    r["page"]["url"],
                                    r["page"]["ip"] if "ip" in r["page"] else "",
                                    r["_id"]
                                ))
                        else:
                            print("Nothing found")
                    else:
                        print("Nothing found")
                    # brief sleeping time to avoid overloading URL Scan
                    time.sleep(0.5)
            elif args.subcommand == 'quota':
                if us.api_key:
                    print(json.dumps(us.quota(), sort_keys=True, indent=4))
                else:
                    print("You need to configure a UrlScan key to check your quota")
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data):
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
