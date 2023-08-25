#! /usr/bin/env python
from datetime import datetime

import requests

from .base import HarpoonPlugin


class Tor(HarpoonPlugin):
    """
    # Tor

    **Check if an IP is a Tor exit node listed in the public list https://check.torproject.org/torbulkexitlist**

    * `harpoon tor IP`
    """

    name = "tor"
    description = "Check if an IP is a Tor exit node listed in the public list"

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.add_argument("IP", help="IP Address")

    def get_list(self):
        r = requests.get("https://check.torproject.org/torbulkexitlist")
        if r.status_code == 200:
            res = r.text.split("\n")
            try:
                res.remove("")
            except ValueError:
                pass
            return res
        return None

    def fetch(self):
        ip = self.unbracket(self.args.IP)
        if not self.is_ip(ip):
            print("Invalid IP address")
            return

        ips = self.get_list()
        if ips:
            if ip in ips:
                self.results = {ip: "Tor exit node"}
            else:
                self.results = {ip: "not a Tor exit node currently"}
        else:
            print("Impossible to get the Tor Exit node list")

    def display_txt(self):
        ip = next(iter(self.results))
        print("{}: {}".format(ip, self.results[ip]))

    def intel_ip(self, ip: str):
        ips = self.get_list()
        if ip in ips:
            self.reports.append(
                {
                    "date": datetime.now(),
                    "title": "Currently a Tor Exit Node",
                    "url": "https://check.torproject.org/torbulkexitlist",
                    "source": self.__class__.__name__,
                }
            )
