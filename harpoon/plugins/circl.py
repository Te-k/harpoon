#! /usr/bin/env python
import pypdns
import pytz

from .base import HarpoonPlugin


class Circl(HarpoonPlugin):
    """
    # Circl plugin

    **Query CIRCL passive DNS database (https://www.circl.lu/services/passive-dns/)**

    * Search for a domain : `harpoon circl DOMAIN`
    """

    name = "circl"
    description = "Request the CIRCL passive DNS database"
    config_structure = ["user", "pass"]

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.add_argument("DOMAIN", help="Domain")

    def fetch(self):
        x = pypdns.PyPDNS(basic_auth=(self.config["user"], self.config["pass"]))
        self.results = x.query(self.unbracket(self.args.DOMAIN))

    def display_txt(self):
        for entry in self.results:
            print(
                "{} - {} - {} {} {}".format(
                    entry["time_first"],
                    entry["time_last"],
                    entry["rrname"],
                    entry["rrtype"],
                    entry["rdata"],
                )
            )

    def intel_domain(self, domain):
        x = pypdns.PyPDNS(basic_auth=(self.config["user"], self.config["pass"]))
        res = x.query(domain)
        for answer in res:
            self.passive_dns.append(
                {
                    "ip": answer["rdata"],
                    "first": answer["time_first"].astimezone(pytz.utc),
                    "last": answer["time_last"].astimezone(pytz.utc),
                    "source": "CIRCL",
                }
            )
