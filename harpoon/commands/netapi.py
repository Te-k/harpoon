#! /usr/bin/env python
import json
import os
import sys
import time
from datetime import datetime

from harpoon.commands.base import Command
from harpoon.lib.netapi import NetAPI, NetAPIError
from harpoon.lib.utils import unbracket


class CommandNetAPI(Command):
    """
    # NetAPI

    **Query the NetAPI JSON API (https://netapi.com/help/api/#json-api)**

    Free, no key needed. A NetAPI account token can be added to the
    configuration to raise the request limits.

    * Rank of a domain in the NetAPI Top 1M and its status in the compromised
      domain feed: `harpoon netapi domain DOMAIN`
    * Same for a list of domains in a file: `harpoon netapi file FILE`
    * Domains registered in the last days whose name contains a text:
      `harpoon netapi new TEXT` (`--days 1..7`, `--tld com`, `--match starts`)
    * Figures of a TLD (registered domains, daily changes, compromised share,
      sites in the Top 1M): `harpoon netapi tld TLD`
    """

    name = "netapi"
    description = "Query NetAPI: Top 1M rank, compromised feed, new domains, TLD figures"
    config = {"NetAPI": []}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help="Subcommand")
        parser_a = subparsers.add_parser(
            "domain", help="Top 1M rank and compromised feed status of a domain"
        )
        parser_a.add_argument("DOMAIN", help="Domain")
        parser_a.add_argument(
            "--json", "-j", action="store_true", help="Show the raw JSON answers"
        )
        parser_a.set_defaults(subcommand="domain")
        parser_b = subparsers.add_parser(
            "file", help="Top 1M rank and compromised feed status of a list of domains"
        )
        parser_b.add_argument("FILE", help="File containing a list of domains")
        parser_b.add_argument(
            "--delay",
            "-d",
            type=int,
            default=4,
            help="Delay between two domains in seconds (default 4: two requests per domain, "
            "30 requests a minute without an account token)",
        )
        parser_b.set_defaults(subcommand="file")
        parser_c = subparsers.add_parser(
            "new", help="Domains registered in the last days whose name contains a text"
        )
        parser_c.add_argument("TEXT", help="Text to search for (at least 4 characters)")
        parser_c.add_argument(
            "--days", type=int, default=7, help="Look back 1 to 7 days (default 7)"
        )
        parser_c.add_argument("--tld", "-t", help="Limit the search to one TLD")
        parser_c.add_argument(
            "--match",
            "-m",
            choices=["contains", "starts"],
            default="contains",
            help="Match type (default contains)",
        )
        parser_c.add_argument(
            "--limit", "-l", type=int, default=100, help="Maximum number of results"
        )
        parser_c.add_argument(
            "--json", "-j", action="store_true", help="Show the raw JSON answer"
        )
        parser_c.set_defaults(subcommand="new")
        parser_d = subparsers.add_parser("tld", help="Figures of a TLD")
        parser_d.add_argument("TLD", help="TLD, for example com or co.uk")
        parser_d.add_argument(
            "--json", "-j", action="store_true", help="Show the raw JSON answer"
        )
        parser_d.set_defaults(subcommand="tld")
        self.parser = parser

    def client(self):
        key = None
        if "NetAPI" in self._config_data:
            key = self._config_data["NetAPI"].get("key", "") or None
        return NetAPI(key=key)

    def check_domain(self, netapi, domain):
        """
        Returns the Top 1M rank answer and the compromised feed answer of a domain
        """
        return netapi.domain_rank(domain), netapi.compromised_check(domain)

    def rank_line(self, rank):
        if rank["in_top_1m"]:
            return "NetAPI Top 1M: rank {} ({} among .{} sites, snapshot {})".format(
                rank["rank"], rank["rank_in_tld"], rank["tld"], rank["snapshot_date"]
            )
        return "NetAPI Top 1M: not in the current list"

    def compromised_line(self, comp):
        if comp["listed_now"]:
            return "Compromised feed: listed now (since {}, last seen {}, reason: {})".format(
                comp["first_seen"], comp["last_seen"], comp["block_reason"]
            )
        if comp["listed_ever"]:
            return (
                "Compromised feed: listed in the past ({} to {}, reason: {}), "
                "not seen in the last 24 hours".format(
                    comp["first_seen"], comp["last_seen"], comp["block_reason"]
                )
            )
        return "Compromised feed: not listed"

    def run(self, args, plugins):
        netapi = self.client()
        if "subcommand" in args:
            try:
                if args.subcommand == "domain":
                    domain = unbracket(args.DOMAIN)
                    rank, comp = self.check_domain(netapi, domain)
                    if args.json:
                        print(json.dumps({"rank": rank, "compromised": comp}, indent=4))
                    else:
                        print(domain)
                        print(self.rank_line(rank))
                        print(self.compromised_line(comp))
                elif args.subcommand == "file":
                    if not os.path.isfile(args.FILE):
                        print("This file does not exist")
                        sys.exit(1)
                    with open(args.FILE) as f:
                        domains = [d.strip() for d in f.read().split("\n") if d.strip()]
                    print("Domain;Top 1M rank;Rank in TLD;Listed now;Listed ever;First seen;Last seen;Reason")
                    for i, d in enumerate(domains):
                        domain = unbracket(d)
                        try:
                            rank, comp = self.check_domain(netapi, domain)
                        except NetAPIError as e:
                            print("{};;;;;;;{}".format(domain, e.message))
                        else:
                            print(
                                "{};{};{};{};{};{};{};{}".format(
                                    domain,
                                    rank["rank"] or "",
                                    rank["rank_in_tld"] or "",
                                    "yes" if comp["listed_now"] else "no",
                                    "yes" if comp["listed_ever"] else "no",
                                    comp["first_seen"] or "",
                                    comp["last_seen"] or "",
                                    comp["block_reason"] or "",
                                )
                            )
                        if i < len(domains) - 1:
                            time.sleep(args.delay)
                elif args.subcommand == "new":
                    res = netapi.search_new(
                        args.TEXT,
                        days=args.days,
                        tld=args.tld,
                        match=args.match,
                        limit=args.limit,
                    )
                    if args.json:
                        print(json.dumps(res, indent=4))
                    else:
                        for r in res["results"]:
                            print("{}\t{}".format(r["added_on"], r["domain"]))
                        print(
                            "{} domain(s) registered since {}{}".format(
                                res["count"],
                                res["since"],
                                " (more results exist, raise --limit)" if res["truncated"] else "",
                            )
                        )
                elif args.subcommand == "tld":
                    res = netapi.tld_stats(args.TLD.lower().lstrip("."))
                    if args.json:
                        print(json.dumps(res, indent=4))
                    else:
                        print(".{} ({})".format(res["tld"], res["registry"] or "registry unknown"))
                        print(
                            "Registered domains: {:,} (snapshot {}, rank {} of {} TLDs by size)".format(
                                res["domains"],
                                res["snapshot_date"],
                                res["rank_by_size"],
                                res["zones_total"],
                            )
                        )
                        if res["updated_daily"]:
                            print(
                                "Last 24 hours: {:,} new, {:,} deleted".format(
                                    res["new_24h"] or 0, res["deleted_24h"] or 0
                                )
                            )
                        for period in ("30d", "365d"):
                            change = res["change"].get(period)
                            if change:
                                print(
                                    "Change over {}: {:+,} domains ({:+.2f}%)".format(
                                        period, change["domains"], change["pct"]
                                    )
                                )
                        if res["compromised"]:
                            print(
                                "Compromised feed: {:,} domains ({}% of the zone)".format(
                                    res["compromised"]["domains"],
                                    res["compromised"]["share_pct"],
                                )
                            )
                        if res["top_1m"]:
                            print(
                                "Sites in the Top 1M: {:,} (rank {} among TLDs)".format(
                                    res["top_1m"]["sites"], res["top_1m"]["rank_among_tlds"]
                                )
                            )
                        print(res["page"])
                else:
                    self.parser.print_help()
            except NetAPIError as e:
                print("NetAPI error: {}".format(e.message))
                sys.exit(1)
        else:
            self.parser.print_help()

    def intel_domain(self, query, data):
        print("[+] Checking NetAPI...")
        netapi = self.client()
        try:
            rank, comp = self.check_domain(netapi, query)
        except NetAPIError as e:
            print("NetAPI query failed: {}".format(e.message))
            return
        if rank["in_top_1m"]:
            data["reports"].append(
                {
                    "date": "",
                    "title": "Domain ranked {} in the NetAPI Top 1M ({} among .{} sites)".format(
                        rank["rank"], rank["rank_in_tld"], rank["tld"]
                    ),
                    "url": rank["links"]["top_1m"],
                    "source": "NetAPI",
                }
            )
        if comp["listed_ever"]:
            if comp["listed_now"]:
                title = "Domain listed in the NetAPI compromised feed (seen in the last 24 hours, reason: {})".format(
                    comp["block_reason"]
                )
            else:
                title = "Domain listed in the NetAPI compromised feed in the past (last seen {}, reason: {})".format(
                    comp["last_seen"], comp["block_reason"]
                )
            try:
                first_seen = datetime.strptime(comp["first_seen"], "%Y-%m-%d")
            except (TypeError, ValueError):
                first_seen = ""
            data["reports"].append(
                {
                    "date": first_seen,
                    "title": title,
                    "url": comp["lists"]["page"],
                    "source": "NetAPI",
                }
            )
