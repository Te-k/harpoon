#! /usr/bin/env python
import pypdns
from harpoon.commands.base import Command
from harpoon.lib.utils import json_serial, unbracket
import json


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
