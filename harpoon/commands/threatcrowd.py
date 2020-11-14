#! /usr/bin/env python3

import json

import requests
from harpoon.commands.base import Command


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


    * Query for an email: `harpoon threatcrowd email EMAIL`
    * Query for a domain: `harpoon threatcrowd domain DOMAIN`
    * Query for a IP: `harpoon threatcrowd ip IP`
    * Query for a antivirus: `harpoon threatcrowd antivirus MALWARE`
    * Query for a filehash: `harpoon threatcrowd file HASH`
    """

    name = "threatcrowd"
    description = "Request the ThreatCrowd API"
    base_url = "http://www.threatcrowd.org/searchApi/v2/"

    def add_arguments(self, parser):
        parser.add_argument("--email", "-e", help="Query an email")
        parser.add_argument("--ip", "-i", help="Query an IP address")
        parser.add_argument("--domain", "-d", help="Query a domain")
        parser.add_argument(
            "--antivirus", "-a", help="Query an antivirus for malware hashes"
        )
        parser.add_argument("--file", "-f", help="Query for a file hash")
        self.parser = parser

    def query(self, queryType, query):
        if queryType == "file":
            res = requests.get(
                self.base_url + queryType + "/report/", {"resource": query}
            ).text
        else:
            res = requests.get(
                self.base_url + queryType + "/report/", {queryType: query}
            ).text
        return res

    def pretty_print(self, data):
        d = json.loads(data)
        print(json.dumps(d, indent=4, sort_keys=True))

    def run(self, conf, args, plugins):
        if args.ip:
            res = self.query("ip", args.ip)
            self.pretty_print(res)
        elif args.email:
            res = self.query("email", args.email)
            self.pretty_print(res)
        elif args.domain:
            res = self.query("domain", args.domain)
            self.pretty_print(res)
        elif args.antivirus:
            res = self.query("antivirus", args.antivirus)
            self.pretty_print(res)
        elif args.file:
            res = self.query("file", args.file)
            self.pretty_print(res)
        else:
            self.parser.print_help()
