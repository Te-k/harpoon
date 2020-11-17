#! /usr/bin/env python
import json
import pypdns
import pytz
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.utils import json_serial, unbracket


class CommandCircl(Command):
    """
    # Circl plugin

    **Query CIRCL passive DNS database (https://www.circl.lu/services/passive-dns/)**

    * Search for a domain : `harpoon circl DOMAIN`
    """
    name = "circl"
    description = "Request the CIRCL passive DNS database"
    config = {'Circl': ['user', 'pass']}

    def add_arguments(self, parser):
        parser.add_argument('DOMAIN', help='Domain')
        self.parser = parser

    def run(self, conf, args, plugins):
        x = pypdns.PyPDNS(
                basic_auth=(
                    conf['Circl']['user'],
                    conf['Circl']['pass']
                )
        )
        res = x.query(unbracket(args.DOMAIN))
        print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))

    def intel(self, type, query, data, conf):
        if type == "domain":
            print("[+] Downloading CIRCL passive DNS information....")
            x = pypdns.PyPDNS(
                basic_auth=(conf["Circl"]["user"], conf["Circl"]["pass"])
            )
            res = x.query(query)
            for answer in res:
                data["passive_dns"].append(
                    {
                        "ip": answer["rdata"],
                        "first": answer["time_first"].astimezone(pytz.utc),
                        "last": answer["time_last"].astimezone(pytz.utc),
                        "source": "CIRCL",
                    }
                )
