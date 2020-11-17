#! /usr/bin/env python
import json
import requests
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket, is_ip


class CommandTor(Command):
    """
    # Tor

    **Check if an IP is a Tor exit node listed in the public list https://check.torproject.org/torbulkexitlist**

    * `harpoon tor IP`
    """
    name = "tor"
    description = "Check if an IP is a Tor exit node listed in the public list"
    config = {"Tor": []}

    def add_arguments(self, parser):
        parser.add_argument('IP',  help='IP Address')
        self.parser = parser

    def get_list(self):
        r = requests.get("https://check.torproject.org/torbulkexitlist")
        if r.status_code == 200:
            res = r.text.split('\n')
            try:
                res.remove('')
            except ValueError:
                pass
            return res
        return None

    def run(self, conf, args, plugins):
        if not is_ip(unbracket(args.IP)):
            print("Invalid IP address")
            sys.exit(-1)
        ips = self.get_list()
        if ips:
            if unbracket(args.IP) in ips:
                print("{} is a Tor Exit node".format(unbracket(args.IP)))
            else:
                print("{} is not listed in the Tor Exit node public list".format(unbracket(args.IP)))
        else:
            print("Impossible to reach the Tor Exit node list")

    def intel(self, type, query, data, conf):
        if type == "ip":
            print("[+] Checking Tor exit nodes...")
            ips = self.get_list()
            if query.strip() in ips:
                data["reports"].append({
                    "date": None,
                    "title": "{} is a Tor Exit Node".format(query),
                    "url": "",
                    "source": "TorExit"
                })
