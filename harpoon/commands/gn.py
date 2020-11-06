#! /usr/bin/env python3
import json
import sys

from greynoise import GreyNoise
from harpoon.commands.base import Command


class CommandGreyNoise(Command):
    """
    # GreyNoise

    See https://github.com/Grey-Noise-Intelligence/api.greynoise.io

    * List tags: `harpoon greynoise -l`
    * Search for an IP: `harpoon greynoise -i IP`
    * Search for a tag with csv output:  `harpoon greynoise -t CENSYS -f csv`
    """

    name = "greynoise"
    description = "Request Grey Noise API"
    config = {"GreyNoise": ["key"]}

    def add_arguments(self, parser):
        parser.add_argument("--list", "-l", help="List tags", action="store_true")
        parser.add_argument("--ip", "-i", help="Query an IP address")
        parser.add_argument("--tag", "-t", help="Query a tag")
        parser.add_argument(
            "--format",
            "-f",
            help="Output format",
            choices=["csv", "json"],
            default="json",
        )
        self.parser = parser

    def run(self, conf, args, plugins):
        if conf["GreyNoise"]["key"] == "":
            print("You need to set your API key with GreyNoise")
            sys.exit()
        gn = GreyNoise(api_key=conf["GreyNoise"]["key"])
        if args.ip:
            res = gn.ip(args.ip)
            if args.format == "json":
                print(json.dumps(res, indent=4, sort_keys=True))
            else:
                for k, v in res.items():
                    print(k, ",", v)
        else:
            self.parser.print_help()
