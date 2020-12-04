#! /usr/bin/env python
import sys
import json
import pytz
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket
from harpoon.lib.pulsedive import PulseDive, PulseDiveError, PulseDiveNotFound
from harpoon.lib.utils import json_serial


class CommandPulseDive(Command):
    """
    # PulseDive plugin

    Queries https://pulsedive.com/ API

    * Search on a domain or IP : `harpoon pulsedive indicator DOMAIN`
    * Search for domains related to an IP : `harpoon pulsedive links IP`
    * Search on a threat : `harpoon pulsedive threat zeus`
    """
    name = "pulsedive"
    description = "Request PulseDive API"
    config = {'PulseDive': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('indicator', help='Request info on an indicator')
        parser_a.add_argument('IOC', help='Indicator')
        parser_a.add_argument('--history', '-H', action="store_true",
                help='Also queries historical data')
        parser_a.set_defaults(subcommand='indicator')
        parser_b = subparsers.add_parser('links', help='Identify links with other indicators')
        parser_b.add_argument('IOC', help='Indicator')
        parser_b.set_defaults(subcommand='links')
        parser_c = subparsers.add_parser('properties', help='Identify properties of an indicator')
        parser_c.add_argument('IOC', help='Indicator')
        parser_c.set_defaults(subcommand='properties')
        parser_d = subparsers.add_parser('threat', help='Get information on a threat')
        parser_d.add_argument('THREAT', help='Threat such as zeus')
        parser_d.set_defaults(subcommand='threat')
        self.parser = parser

    def run(self, conf, args, plugins):
        p = PulseDive(conf['PulseDive']['key'])
        if 'subcommand' in args:
            if args.subcommand == "indicator":
                res = p.indicators_by_value(unbracket(args.IOC), historical=args.history)
                print(json.dumps(res, sort_keys=True, indent=4))
            elif args.subcommand == "links":
                res = p.indicators_by_value_links(args.IOC)
                print(json.dumps(res, sort_keys=True, indent=4))
            elif args.subcommand == "properties":
                res = p.indicators_by_value_properties(args.IOC)
                print(json.dumps(res, sort_keys=True, indent=4))
            elif args.subcommand == "threat":
                res = p.threat(args.THREAT)
                print(json.dumps(res, sort_keys=True, indent=4))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        if type == "domain":
            pd = PulseDive(conf['PulseDive']['key'])
            print("[+] Checking PulseDive...")
            try:
                res = pd.indicators_by_value(unbracket(query), historical=True)
                if "properties" in res:
                    if "dns" in res["properties"]:
                        for ip in res["properties"]["dns"]:
                            if ip["name"] == "A":
                                data["passive_dns"].append({
                                    "ip": ip["value"],
                                    "first": parse(ip["stamp_seen"]).astimezone(pytz.utc),
                                    "last": None,
                                    "source": "PulseDive"
                                })
                    if "threats" in res:
                        if len(res["threats"]) > 0:
                            data["reports"].append({
                                "date": None,
                                "source": "PulseDive",
                                "title": "Identified as related to {}".format(", ".join([r["name"] for r in res["threats"]])),
                                "url": ""
                            })
                res = pd.indicators_by_value_links(unbracket(query))
                if "Related URLs" in res:
                    for url in res["Related URLs"]:
                        data["urls"].append({
                            "source": "PulseDive",
                            "url": url["indicator"],
                            "ip": "",
                            "date": parse(url["stamp_linked"]).astimezone(pytz.utc)
                        })
            except PulseDiveError:
                pass
        elif type == "ip":
            pd = PulseDive(conf['PulseDive']['key'])
            print("[+] Checking PulseDive...")
            try:
                res = pd.indicators_by_value(unbracket(query), historical=True)
                if "attributes" in res:
                    if "port" in res["attributes"]:
                        for p in res["attributes"]["port"]:
                            data["ports"].append({
                                "port": p,
                                "source": "PulseDive",
                                "info": ""
                            })
                if "properties" in res:
                    if "dns" in res["properties"]:
                        for ip in res["properties"]["dns"]:
                            if ip["name"] == "A":
                                data["passive_dns"].append({
                                    "domain": ip["value"],
                                    "first": parse(ip["stamp_seen"]).astimezone(pytz.utc),
                                    "last": None,
                                    "source": "PulseDive"
                                })
                    if "threats" in res:
                        if len(res["threats"]) > 0:
                            data["reports"].append({
                                "date": None,
                                "source": "PulseDive",
                                "title": "Identified as related to {}".format(", ".join([r["name"] for r in res["threats"]])),
                                "url": ""
                            })
                res = pd.indicators_by_value_links(unbracket(query))
                if "Related URLs" in res:
                    for url in res["Related URLs"]:
                        data["urls"].append({
                            "source": "PulseDive",
                            "url": url["indicator"],
                            "ip": "",
                            "date": parse(url["stamp_linked"]).astimezone(pytz.utc)
                        })
            except PulseDiveError:
                pass
