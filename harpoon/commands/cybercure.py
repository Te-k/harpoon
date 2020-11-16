#! /usr/bin/env python
import sys
import os
import json
from harpoon.commands.base import Command
from harpoon.lib.utils import unbracket
from harpoon.lib.cybercure import CyberCure, CyberCureError


class CommandCyberCure(Command):
    """
    # cybercure.ai plugin

    **Check if intelligence on an IP exists**

    Query cybercure API:
    ```
    harpoon cybercure ip 184.186.250.211
    {
    "exists": true,
    "indicator": "184.186.250.211",
    "status": 1,
    "visual": "http://www.cybercure.ai/intel/ip/184.186.250.211"
    }
    ```

    """
    name = "cybercure"
    description = "Search cybercure.ai intelligence database for specific indicators."

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('ip', help='Returns a response whether an indicator exists in cybercure.ai database, if it is exists it will provide also a link for visual presentation of the indicator history.')
        parser_a.add_argument('IP', help='IP address')
        parser_a.set_defaults(subcommand='ip')
        parser_b = subparsers.add_parser('file', help='Information on a list of IPs')
        parser_b.add_argument('FILE', help='Filename')
        parser_b.set_defaults(subcommand='file')
        self.parser = parser

    def run(self, conf, args, plugins):
        cybercure = CyberCure(token='reserved_for_future')
        if 'subcommand' in args:
            if args.subcommand == 'ip':
                try:
                    infos = cybercure.get_infos(unbracket(args.IP))
                except CyberCureError:
                    print("Invalid request")
                else:
                    print(json.dumps(infos,  sort_keys=True, indent=4, separators=(',', ': ')))
            elif args.subcommand == 'file':
                if os.path.isfile(args.FILE):
                    with open(args.FILE) as f:
                        data = f.read().split("\n")
                    print("IP;Exists;Details")
                    for d in data:
                        if d.strip() == '':
                            continue
                        ip = unbracket(d.strip())
                        try:
                            infos = cybercure.get_infos(ip)
                        except CyberCureError:
                            print("%s;;" % ip)
                        else:
                            print ("%s;%s;%s" % (
                                    ip,
                                    infos['exists'],
                                    infos['visual'] if 'visual' in infos else ''
                                )
                            )
                else:
                    print("This file does not exist")
                    sys.exit(1)
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
