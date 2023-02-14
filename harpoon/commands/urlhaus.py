#! /usr/bin/env python3
import json

import pytz
from dateutil.parser import parse

from harpoon.commands.base import Command
from harpoon.lib.urlhaus import UrlHaus, UrlHausError
from harpoon.lib.utils import unbracket


class CommandUrlhaus(Command):
    """
    # URLhaus

    Query https://urlhaus.abuse.ch/ API

    * Get information on an IP : `harpoon urlhaus get-host 111.174.128.51`
    * Get information on a hash : `harpoon urlhaus get-payload [HASH]`
    * Download a sample : `harpoon urlhaus get-payload [HASH]`
    """

    name = "urlhaus"
    description = "Request urlhaus.abuse.ch API"
    config = {"UrlHaus": ["key"]}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help="Subcommand")
        parser_a = subparsers.add_parser("get-url", help="Request info on a URL")
        parser_a.add_argument("url", help="url")
        parser_a.set_defaults(subcommand="get-url")

        parser_b = subparsers.add_parser(
            "get-host",
            help="Request info on a host: IPv4 address, hostname or domain name",
        )
        parser_b.add_argument("host", help="host")
        parser_b.set_defaults(subcommand="get-host")

        parser_c = subparsers.add_parser(
            "get-payload", help="Request info about a payload: md5 or sha256"
        )
        parser_c.add_argument("payload", help="payload")
        parser_c.set_defaults(subcommand="get-payload")

        parser_d = subparsers.add_parser(
            "get-tag",
            help="Request info about a tag: Gozi, Trickbot...",
        )
        parser_d.add_argument("tag", help="tag")
        parser_d.set_defaults(subcommand="get-tag")

        parser_d = subparsers.add_parser(
            "get-signature", help="Request info about a signature: Gozi, Trickbot"
        )
        parser_d.add_argument("signature", help="signature")
        parser_d.set_defaults(subcommand="get-signature")

        parser_e = subparsers.add_parser(
            "get-sample", help="Request a malware sample identified by a hash (sha256)"
        )
        parser_e.add_argument("hash", help="hash")
        parser_e.set_defaults(subcommand="get-sample")

        self.parser = parser

    def run(self, args, plugins):
        urlhaus = UrlHaus(self._config_data["UrlHaus"]["key"])
        if "subcommand" in args:
            try:
                if args.subcommand == "get-url":
                    res = urlhaus.get_url(args.url)
                    print(json.dumps(res, sort_keys=False, indent=4))
                elif args.subcommand == "get-host":
                    res = urlhaus.get_host(unbracket(args.host))
                    print(json.dumps(res, sort_keys=False, indent=4))
                elif args.subcommand == "get-payload":
                    res = urlhaus.get_payload(args.payload)
                    print(json.dumps(res, sort_keys=False, indent=4))
                elif args.subcommand == "get-tag":
                    res = urlhaus.get_tag(args.tag)
                    print(json.dumps(res, sort_keys=False, indent=4))
                elif args.subcommand == "get-signature":
                    res = urlhaus.get_signature(args.signature)
                    print(json.dumps(res, sort_keys=False, indent=4))
                elif args.subcommand == "get-sample":
                    data = urlhaus.get_sample(args.hash)
                    if data:
                        with open(args.hash, "wb") as f:
                            f.write(data)
                        print("Sample saved as {}".format(args.hash))
                    else:
                        print("Sample not found")
                else:
                    self.parser.print_help()
            except UrlHausError:
                print("UrlHaus : query failed ¯\\_(ツ)_/¯")
        else:
            self.parser.print_help()

    def intel(self, type, query, data):
        if type in ["domain", "ip"]:
            print("[+] Checking URLHaus...")
            try:
                urlhaus = UrlHaus(self._config_data["UrlHaus"]["key"])
                res = urlhaus.get_host(unbracket(query))
            except UrlHausError:
                print("Error with the query")
            else:
                if "urls" in res:
                    for r in res["urls"]:
                        data["urls"].append({
                            "date": parse(r["date_added"]).astimezone(pytz.utc),
                            "url": r["url"],
                            "ip": "",
                            "source": "UrlHaus",
                        })
        elif type == "hash":
            print("[+] Checking URLHaus...")
            try:
                urlhaus = UrlHaus(self._config_data["UrlHaus"]["key"])
                res = urlhaus.get_payload(query)
            except UrlHausError:
                print("Error with the query")
            else:
                if "urlhaus_download" in res:
                    data["samples"].append({
                        "date": parse(res["firstseen"]),
                        "source": "UrlHaus",
                        "url": res["urlhaus_download"]
                    })
                if "urls" in res:
                    for r in res["urls"]:
                        data["urls"].append({
                            "date": parse(r["firstseen"]) if "firstseen" in r else "",
                            "url": r["url"],
                            "link": r["urlhaus_reference"],
                            "source": "UrlHaus"
                        })
