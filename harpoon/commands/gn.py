#! /usr/bin/env python3
import json
import logging

from dateutil.parser import parse
from greynoise import GreyNoise

from harpoon.commands.base import Command


class GreynoiseError(Exception):
    pass


class CommandGreyNoise(Command):
    """
    # GreyNoise

    See https://developer.greynoise.io/

    * To use GreyNoise Community (Free) API, set api_type = "community" in config.
    * Commuinty API only supports IP lookup command

    * List tags: `harpoon greynoise -l` (default output as json)
    * Search for an IP: `harpoon greynoise -i IP`
    * Run a GNQL query: `harpoon greynoise -q "classification:malicious tags:'emotet'"`
    """

    name = "greynoise"
    description = "Request information from GreyNoise API"
    config = {"GreyNoise": ["key", "api_type"]}

    def add_arguments(self, parser):
        parser.add_argument("--ip", "-i", help="Query an IP address")
        parser.add_argument("--list", "-l", help="List tags", action="store_true")
        parser.add_argument(
            "--query",
            "-q",
            help="Run a gnql query. Example: \"classification:malicious tags:'emotet'\" ",
        )
        parser.add_argument(
            "--format",
            "-f",
            help="Output format",
            choices=["csv", "json"],
            default="json",
        )
        self.parser = parser

    def print_results(self, res, args):
        if args.format == "json":
            print(json.dumps(res, indent=4, sort_keys=True))
        else:
            for k, v in res.items():
                print(k, ",", v)
        return

    def run(self, args, plugins):
        logging.getLogger("greynoise").setLevel(logging.CRITICAL)
        if self._config_data["GreyNoise"]["api_type"].lower() == "community":
            gn = GreyNoise(
                api_key=self._config_data["GreyNoise"]["key"],
                integration_name="Harpoon (https://github.com/Te-k/harpoon)",
                offering="community",
            )
        else:
            gn = GreyNoise(
                api_key=self._config_data["GreyNoise"]["key"],
                integration_name="Harpoon (https://github.com/Te-k/harpoon)",
            )
        if args.ip:
            res = gn.ip(args.ip)
            self.print_results(res, args)
        elif args.query:
            res = gn.query(args.query)
            self.print_results(res, args)
        elif args.list:
            res = gn.metadata()
            self.print_results(res, args)
        else:
            self.parser.print_help()

    def intel_ip(self, query, data):
        print("[+] Checking GreyNoise...")
        logging.getLogger("greynoise").setLevel(logging.CRITICAL)
        if self._config_data["GreyNoise"]["api_type"].lower() == "community":
            gn = GreyNoise(
                api_key=self._config_data["GreyNoise"]["key"],
                integration_name="Harpoon (https://github.com/Te-k/harpoon)",
                offering="community",
            )
            res = gn.ip(query)
            if res["noise"]:
                data["reports"].append(
                    {
                        "url": "https://viz.greynoise.io/ip/{}".format(query),
                        "title": "Seen by GreyNoise as {}".format(res["name"]),
                        "date": parse(res["last_seen"]) if "last_seen" in res else "",
                        "source": "GreyNoise",
                    }
                )
        else:
            gn = GreyNoise(
                api_key=self._config_data["GreyNoise"]["key"],
                integration_name="Harpoon (https://github.com/Te-k/harpoon)",
            )
            res = gn.ip(query)
            if res["seen"]:
                data["reports"].append(
                    {
                        "url": "https://viz.greynoise.io/ip/{}".format(query),
                        "title": "Seen by GreyNoise as {}".format(
                            ", ".join(res["tags"])
                        ),
                        "date": parse(res["last_seen"]) if "last_seen" in res else "",
                        "source": "GreyNoise",
                    }
                )
