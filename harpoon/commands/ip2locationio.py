#! /usr/bin/env python
import json
import os
import sys
import time

from harpoon.commands.base import Command
from harpoon.lib.ip2locationio import IP2Locationio, IP2LocationioError
from harpoon.lib.utils import unbracket


class CommandIPInfo(Command):
    """
    # IP2Location.io plugin

    **Query IP2Location.io API**

    * Get info on an IP : `harpoon ip2locationio ip IP`
    * Get infos on a list of IPs in a file : `harpoon ip2locationio file FILE`
    """

    name = "ip2locationio"
    description = "Request IP2Location.io information"
    config = {"IP2Locationio": ["token"]}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help="Subcommand")
        parser_a = subparsers.add_parser("ip", help="Information on an IP")
        parser_a.add_argument("IP", help="IP address")
        parser_a.set_defaults(subcommand="ip")
        parser_b = subparsers.add_parser("file", help="Information on a list of IPs")
        parser_b.add_argument("FILE", help="Filename")
        parser_b.add_argument(
            "--delay",
            "-d",
            type=int,
            default=1,
            help="Delay between two queries in seconds",
        )
        parser_b.set_defaults(subcommand="file")
        self.parser = parser

    def run(self, args, plugins):
        ip2locationio = IP2Locationio(token=self._config_data["IP2Locationio"]["token"])
        if "subcommand" in args:
            if args.subcommand == "ip":
                try:
                    infos = ip2locationio.get_infos(unbracket(args.IP))
                except IP2LocationioError:
                    print("Invalid request")
                else:
                    print(
                        json.dumps(
                            infos, sort_keys=True, indent=4, separators=(",", ": ")
                        )
                    )
            elif args.subcommand == "file":
                if os.path.isfile(args.FILE):
                    with open(args.FILE) as f:
                        data = f.read().split("\n")
                    print(
                        "IP;Domain;City;Region;Country;Location;"
                        + "ISP;ASN;AS Name;"
                        + "Is Proxy;Proxy Type;Threat Type;Last Seen in"
                    )
                    for d in data:
                        if d.strip() == "":
                            continue
                        ip = unbracket(d.strip())
                        try:
                            infos = ip2locationio.get_infos(ip)
                        except IP2LocationioError:
                            print("%s;;;;;;;;;;;;;" % ip)
                        else:
                            loc = str(infos["latitude"]) + "," + str(infos["longitude"])
                            if "proxy" in infos:
                                print(
                                    "%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s"
                                    % (
                                        ip,
                                        infos["domain"] if "domain" in infos else "",
                                        infos["city_name"] if "city" in infos else "",
                                        infos["region_name"]
                                        if "region" in infos
                                        else "",
                                        infos["country_name"]
                                        if "country" in infos
                                        else "",
                                        loc,
                                        infos["isp"] if "isp" in infos else "",
                                        infos["asn"] if "asn" in infos else "",
                                        infos["as"] if "as" in infos else "",
                                        infos["is_proxy"]
                                        if "is_proxy" in infos
                                        else "",
                                        infos["proxy"]["proxy_type"]
                                        if "proxy_type" in infos["proxy"]
                                        else "",
                                        infos["proxy"]["threat"]
                                        if "threat" in infos["proxy"]
                                        else "",
                                        (
                                            str(infos["proxy"]["last_seen"])
                                            + (
                                                " days"
                                                if infos["proxy"]["last_seen"] > 1
                                                else " day"
                                            )
                                        )
                                        if "last_seen" in infos["proxy"]
                                        else "",
                                    )
                                )
                            else:
                                print(
                                    "%s;%s;%s;%s;%s;%s;%s;%s;%s;;;;;"
                                    % (
                                        ip,
                                        infos["domain"] if "domain" in infos else "",
                                        infos["city_name"],
                                        infos["region_name"],
                                        infos["country_name"],
                                        loc,
                                        infos["isp"] if "isp" in infos else "",
                                        infos["asn"] if "asn" in infos else "",
                                        infos["as"] if "as" in infos else "",
                                    )
                                )
                        time.sleep(args.delay)

                else:
                    print("This file does not exist")
                    sys.exit(1)
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
