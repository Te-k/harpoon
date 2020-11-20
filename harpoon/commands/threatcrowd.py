#! /usr/bin/env python3

import json
import requests
import pytz
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.threatcrowd import ThreatCrowd, ThreatCrowdError
from harpoon.lib.utils import unbracket


class CommandThreatCrowd(Command):
    """
    # ThreatCrowd

    See: https://github.com/AlienVault-OTX/ApiV2

    With the ThreatCrowd API you can search for:

    * Domains
    * IP Addreses
    * E-mail adddresses
    * Filehashes
    * Antivirus detections


    * Query for an email: `harpoon threatcrowd --email EMAIL`
    * Query for a domain: `harpoon threatcrowd --domain DOMAIN`
    * Query for a IP: `harpoon threatcrowd --ip IP`
    * Query for a antivirus: `harpoon threatcrowd --antivirus MALWARE` (ex: plugx)
    * Query for a filehash: `harpoon threatcrowd --file HASH`
    """
    name = "threatcrowd"
    description = "Request the ThreatCrowd API"
    config = {'ThreatCrowd': []}

    def add_arguments(self, parser):
        parser.add_argument("--email", "-e", help="Query an email")
        parser.add_argument("--ip", "-i", help="Query an IP address")
        parser.add_argument("--domain", "-d", help="Query a domain")
        parser.add_argument(
            "--antivirus", "-a", help="Query an antivirus for malware hashes"
        )
        parser.add_argument("--file", "-f", help="Query for a file hash")
        self.parser = parser

    def pretty_print(self, data):
        print(json.dumps(data, indent=4, sort_keys=True))

    def run(self, conf, args, plugins):
        tc = ThreatCrowd()
        try:
            if args.ip:
                self.pretty_print(tc.ip(unbracket(args.ip)))
            elif args.email:
                self.pretty_print(tc.email(args.email))
            elif args.domain:
                self.pretty_print(tc.domain(unbracket(args.domain)))
            elif args.antivirus:
                self.pretty_print(tc.antivirus(args.antivirus))
            elif args.file:
                self.pretty_print(tc.file(args.file))
            else:
                self.parser.print_help()
        except ThreatCrowdError as e:
            print("Query failed: {}".format(e.message))

    def intel(self, type, query, data, conf):
        if type == "domain":
            print("[+] Checking ThreatCrowd...")
            tc = ThreatCrowd()
            try:
                res = tc.domain(query)
                if "resolutions" in res:
                    for d in res["resolutions"]:
                        if d["ip_address"] not in ["-", ""]:
                            try:
                                data["passive_dns"].append({
                                    "ip": d["ip_address"],
                                    "first": parse(d["last_resolved"]).astimezone(pytz.utc),
                                    "last": parse(d["last_resolved"]).astimezone(pytz.utc),
                                    "source": "ThreatCrowd"
                                })
                            except:
                                # Date error
                                pass
                if "hashes" in res:
                    for h in res["hashes"]:
                        data["malware"].append({
                            "hash": h,
                            "source": "ThreatCrowd",
                            "date": ""
                        })
            except ThreatCrowdError as e:
                print("Connection to ThreatCrowd failed: {}".format(e.message))
        elif type == "ip":
            print("[+] Checking ThreatCrowd...")
            tc = ThreatCrowd()
            try:
                res = tc.ip(query)
                if "resolutions" in res:
                    for d in res["resolutions"]:
                        try:
                            data["passive_dns"].append({
                                "domain": d["domain"].strip(),
                                "first": parse(d["last_resolved"]).astimezone(pytz.utc),
                                "last": parse(d["last_resolved"]).astimezone(pytz.utc),
                                "source": "ThreatCrowd"
                            })
                        except:
                            # Date error
                            pass
                if "hashes" in res:
                    for h in res["hashes"]:
                        data["malware"].append({
                            "hash": h,
                            "source": "ThreatCrowd",
                            "date": ""
                        })
            except ThreatCrowdError as e:
                print("Connection to ThreatCrowd failed: {}".format(e.message))
        elif type == "hash":
            print("[+] Checking ThreatCrowd...")
            if len(query.strip()) != 32:
                print("ThreatCrowd only accepts md5 ¯\_(ツ)_/¯")
                return
            tc = ThreatCrowd()
            try:
                res = tc.file(query)
                if "domains" in res:
                    for d in res["domains"]:
                        data["network"].append({
                            "host": d,
                            "source": "ThreatCrowd",
                            "url": res["permalink"]
                        })
                if "ips" in res:
                    for d in res["ips"]:
                        data["network"].append({
                            "host": d,
                            "source": "ThreatCrowd",
                            "url": res["permalink"]
                        })
            except ThreatCrowdError as e:
                print("Connection to ThreatCrowd failed: {}".format(e.message))
