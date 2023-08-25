#! /usr/bin/env python
import time

import pytz
from dateutil.parser import parse

from harpoon.api.urlscan import UrlScanException, UrlScanLibrary, UrlScanQuotaExceeded

from .base import HarpoonPlugin


class UrlScanSearch(HarpoonPlugin):
    name = "search"
    description = "Search in UrlScan"

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.parser.add_argument("QUERY", help="DOMAIN to be queried")

    def fetch(self):
        try:
            key = self.config["key"]
            if key.strip() != "":
                us = UrlScanLibrary(key)
            else:
                us = UrlScanLibrary()
        except KeyError:
            us = UrlScan()

        try:
            self.results = us.search(self.args.QUERY)
        except UrlScanException as e:
            print("Error: {}".format(e.message))

    def display_txt(self):
        if len(self.results["results"]) > 0:
            for r in self.results["results"]:
                print(
                    "{} - {} - {} - https://urlscan.io/result/{}".format(
                        r["task"]["time"],
                        r["page"]["url"],
                        r["page"]["ip"] if "ip" in r["page"] else "",
                        r["_id"],
                    )
                )
        else:
            print("No results for this query")


class UrlScanView(HarpoonPlugin):
    name = "view"
    description = "View a UrlScan analysis"

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.parser.add_argument("UID", help="Uid of the analysis")

    def fetch(self):
        try:
            key = self.config["UrlScan"]["key"]
            if key.strip() != "":
                us = UrlScanLibrary(key)
            else:
                us = UrlScanLibrary()
        except KeyError:
            us = UrlScan()

        try:
            self.results = us.view(self.args.UID)
        except UrlScanException as e:
            print("Error: {}".format(e.message))


class UrlScanList(HarpoonPlugin):
    name = "list"
    description = "Search list of domains or IPs in urlscan"

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.add_argument("FILE", help="File containing IPs or domains")

    def fetch(self):
        try:
            key = self.config["UrlScan"]["key"]
            if key.strip() != "":
                us = UrlScanLibrary(key)
            else:
                us = UrlScanLibrary()
        except KeyError:
            us = UrlScan()

        with open(self.args.FILE) as f:
            data = f.read().split("\n")

        self.results = {}
        for d in data:
            d = d.strip()
            if d == "":
                continue

            try:
                self.results[d] = us.search(d)
            except UrlScanQuotaExceeded as e:
                duration = int(e.message[-13:-9]) + 10
                print("Out of quota, waiting for {} seconds".format(duration))
                time.sleep(duration)
                self.results[d] = us.search(d)

    def display_txt(self):
        if len(self.results) == 0:
            print("Nothing found")
            return

        for entry in self.results:
            for r in self.results[entry]["results"]:
                print(
                    "{} - {} - {} - https://urlscan.io/result/{}".format(
                        r["task"]["time"],
                        r["page"]["url"],
                        r["page"]["ip"] if "ip" in r["page"] else "",
                        r["_id"],
                    )
                )


class UrlScan(HarpoonPlugin):
    """
    # url scan

    Allows to search and scan urls using https://urlscan.io/

    * Query the database : `harpoon urlscan search DOMAIN`
    * View an analysis : `harpoon urlscan view UID`
    """

    name = "urlscan"
    description = "Search and submit urls to urlscan.io"
    # TODO: manage configuration

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.add_subcommand(UrlScanSearch)
        self.add_subcommand(UrlScanView)
        self.add_subcommand(UrlScanList)

    def intel_ip(self, ip: str):
        us = UrlScanLibrary()
        res = us.search(ip)
        if "results" in res:
            for r in res["results"]:
                self.urls.append(
                    {
                        "date": parse(r["task"]["time"]).astimezone(pytz.utc),
                        "url": r["page"]["url"],
                        "ip": r["page"]["ip"] if "ip" in r["page"] else "",
                        "source": "UrlScan",
                    }
                )

    def intel_domain(self, domain: str):
        us = UrlScanLibrary()
        res = us.search(domain)
        if "results" in res:
            for r in res["results"]:
                self.urls.append(
                    {
                        "date": parse(r["task"]["time"]).astimezone(pytz.utc),
                        "url": r["page"]["url"],
                        "ip": r["page"]["ip"] if "ip" in r["page"] else "",
                        "source": "UrlScan",
                    }
                )
