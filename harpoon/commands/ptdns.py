#! /usr/bin/env python
import sys
import json
from harpoon.commands.base import Command
from passivetotal.libs.dns import DnsRequest

class CommandPtDns(Command):
    name = "ptdns"
    description = "Requests Passive Total passive DNS database"
    config = {'PassiveTotal': ['username', 'key']}

    def add_arguments(self, parser):
        parser.add_argument('DOMAIN',  help='DOMAIN to be queried')

    def run(self, conf, args):
        client = DnsRequest(conf['PassiveTotal']['username'], conf['PassiveTotal']['key'])
        raw_results = client.get_passive_dns(
            query=args.DOMAIN,
        )
        print(json.dumps(raw_results,  sort_keys=True, indent=4, separators=(',', ': ')))
