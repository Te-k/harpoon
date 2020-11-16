#! /usr/bin/env python
import datetime
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request

import geoip2.database
import pyasn
import pypdns
import pytz
import requests
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.commands.umbrella import CommandUmbrella
from harpoon.lib.robtex import Robtex, RobtexError
from harpoon.lib.urlhaus import UrlHaus, UrlHausError
from harpoon.lib.urlscan import UrlScan
from harpoon.lib.utils import bracket, unbracket
from harpoon.lib.threatcrowd import ThreatCrowd, ThreatCrowdError
from IPy import IP
from OTXv2 import IndicatorTypes, OTXv2
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.enrichment import EnrichmentRequest
from pybinaryedge import BinaryEdge, BinaryEdgeException, BinaryEdgeNotFound
from pymisp import ExpandedPyMISP
from pythreatgrid2 import ThreatGrid, ThreatGridError
from threatminer import ThreatMiner
from virus_total_apis import PrivateApi, PublicApi


class CommandIntel(Command):
    """
    # Intel

    Gather information from multiple Threat Intelligence platforms

    * **harpoon intel domain DOMAIN**
    """
    name = "intel"
    description = "Gather information on a domain"
    config = None
    geocity = os.path.join(
        os.path.expanduser("~"), ".config/harpoon/GeoLite2-City.mmdb"
    )
    geoasn = os.path.join(os.path.expanduser("~"), ".config/harpoon/GeoLite2-ASN.mmdb")
    asnname = os.path.join(os.path.expanduser("~"), ".config/harpoon/asnnames.csv")
    asncidr = os.path.join(os.path.expanduser("~"), ".config/harpoon/asncidr.dat")

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help="Subcommand")
        parser_a = subparsers.add_parser(
            "domain", help="Gather Threat Intelligence information on a domain"
        )
        parser_a.add_argument("DOMAIN", help="Domain")
        parser_a.add_argument("--all", "-a", action="store_true",
                help="Query all plugins configured and available")
        parser_a.set_defaults(subcommand="domain")
        self.parser = parser

    def run(self, conf, args, plugins):
        if "subcommand" in args:
            if args.subcommand == "domain":
                data = {
                        "passive_dns": [],
                        "urls": [],
                        "malware": [],
                        "files": [],
                        "reports": []
                }
                print("###################### %s ###################" % args.DOMAIN)
                for p in plugins:
                    if args.all:
                        if plugins[p].test_config(conf):
                            plugins[p].intel("domain", unbracket(args.DOMAIN), data, conf)
                    else:
                        if plugins[p].test_config(conf) and plugins[p].check_intel(conf):
                            plugins[p].intel("domain", unbracket(args.DOMAIN), data, conf)
                print("")

                if len(data["reports"]) > 0:
                    print("----------------- Intelligence Report")
                    for report in data["reports"]:
                        print("{} - {} - {} - {}".format(
                            report["date"],
                            report["title"],
                            report["url"],
                            report["source"]
                        ))
                if len(data["malware"]) > 0:
                    print("----------------- Malware")
                    for r in data["malware"]:
                        print(
                            "[%s] %s %s"
                            % (
                                r["source"],
                                r["hash"],
                                r["date"].strftime("%Y-%m-%d") if r["date"] else "",
                            )
                        )
                if len(data["files"]) > 0:
                    print("----------------- Files")
                    for r in data["files"]:
                        if r["date"] != "":
                            print(
                                "[%s] %s (%s)"
                                % (
                                    r["source"],
                                    r["hash"],
                                    r["date"].strftime("%Y-%m-%d"),
                                )
                            )
                        else:
                            print(
                                "[%s] %s"
                                % (
                                    r["source"],
                                    r["hash"],
                                )
                            )
                if len(data["urls"]) > 0:
                    print("----------------- Urls")
                    for r in sorted(data["urls"], key=lambda x: x["date"], reverse=True):
                        print("{:9} {} - {} {}".format(
                                "[" + r["source"] + "]",
                                r["url"],
                                r["ip"],
                                r["date"].strftime("%Y-%m-%d"),
                            )
                        )
                if len(data["passive_dns"]) > 0:
                    print("----------------- Passive DNS")
                    for r in sorted(
                        data["passive_dns"], key=lambda x: x["first"], reverse=True
                    ):
                        print(
                            "[+] %-40s (%s -> %s)(%s)"
                            % (
                                r["ip"],
                                r["first"].strftime("%Y-%m-%d"),
                                r["last"].strftime("%Y-%m-%d"),
                                r["source"],
                            )
                        )
                if sum([len(data[b]) for b in data]) == 0:
                    print("Nothing found")
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
