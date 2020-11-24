#! /usr/bin/env python
import os
import sys
from harpoon.commands.base import Command
from harpoon.lib.utils import unbracket, is_ip


class CommandIntel(Command):
    """
    # Intel

    Gather information from multiple Threat Intelligence platforms

    * **harpoon intel domain DOMAIN**
    """
    name = "intel"
    description = "Gather information on a domain"
    config = None
    geocity = os.path.join(
        os.path.expanduser("~"), ".config/harpoon/GeoLite2-City.mmdb"
    )
    geoasn = os.path.join(os.path.expanduser("~"), ".config/harpoon/GeoLite2-ASN.mmdb")
    asnname = os.path.join(os.path.expanduser("~"), ".config/harpoon/asnnames.csv")
    asncidr = os.path.join(os.path.expanduser("~"), ".config/harpoon/asncidr.dat")

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help="Subcommand")
        parser_a = subparsers.add_parser(
            "domain", help="Gather Threat Intelligence information on a domain"
        )
        parser_a.add_argument("DOMAIN", help="Domain")
        parser_a.add_argument("--all", "-a", action="store_true",
                help="Query all plugins configured and available")
        parser_a.set_defaults(subcommand="domain")
        parser_b = subparsers.add_parser(
            "ip", help="Gather Threat Intelligence information on an IP address"
        )
        parser_b.add_argument("IP", help="IP address")
        parser_b.add_argument("--all", "-a", action="store_true",
                help="Query all plugins configured and available")
        parser_b.set_defaults(subcommand="ip")
        parser_c = subparsers.add_parser(
            "hash", help="Gather Threat Intelligence information on a hash"
        )
        parser_c.add_argument("HASH", help="Hash")
        parser_c.add_argument("--all", "-a", action="store_true",
                help="Query all plugins configured and available")
        parser_c.set_defaults(subcommand="hash")
        self.parser = parser
        self.parser = parser

    def run(self, conf, args, plugins):
        if "subcommand" in args:
            if args.subcommand == "domain":
                data = {
                        "passive_dns": [],
                        "urls": [],
                        "malware": [],
                        "files": [],
                        "reports": [],
                        #"subdomains": []
                }
                print("###################### %s ###################" % args.DOMAIN)
                for p in plugins:
                    if args.all:
                        if plugins[p].test_config(conf):
                            plugins[p].intel("domain", unbracket(args.DOMAIN), data, conf)
                    else:
                        if plugins[p].test_config(conf) and plugins[p].check_intel(conf):
                            plugins[p].intel("domain", unbracket(args.DOMAIN), data, conf)
                print("")

                if len(data["reports"]) > 0:
                    print("----------------- Intelligence Report")
                    for report in data["reports"]:
                        print("{} - {} - {} - {}".format(
                            report["date"].strftime("%Y-%m-%d") if report["date"] else "",
                            report["title"],
                            report["url"],
                            report["source"]
                        ))
                    print("")
                if len(data["malware"]) > 0:
                    print("----------------- Malware")
                    for r in data["malware"]:
                        print(
                            "[%s] %s %s"
                            % (
                                r["source"],
                                r["hash"],
                                r["date"].strftime("%Y-%m-%d") if r["date"] else "",
                            )
                        )
                    print("")
                if len(data["files"]) > 0:
                    print("----------------- Files")
                    for r in data["files"]:
                        if r["date"] != "":
                            print(
                                "[%s] %s (%s)"
                                % (
                                    r["source"],
                                    r["hash"],
                                    r["date"].strftime("%Y-%m-%d"),
                                )
                            )
                        else:
                            print(
                                "[%s] %s"
                                % (
                                    r["source"],
                                    r["hash"],
                                )
                            )
                    print("")
                if len(data["urls"]) > 0:
                    print("----------------- Urls")
                    for r in sorted(data["urls"], key=lambda x: x["date"], reverse=True):
                        print("{:9} {} - {} {}".format(
                                "[" + r["source"] + "]",
                                r["url"],
                                r["ip"],
                                r["date"].strftime("%Y-%m-%d"),
                            )
                        )
                    print("")
                #if len(data["subdomains"]) > 0:
                    #print("----------------- Subdomains")
                    #for r in set(data["subdomains"]):
                        #print(r)
                if len(data["passive_dns"]) > 0:
                    print("----------------- Passive DNS")
                    for r in sorted(
                        data["passive_dns"], key=lambda x: x["first"], reverse=True
                    ):
                        print(
                            "[+] %-40s (%s -> %s)(%s)"
                            % (
                                r["ip"],
                                r["first"].strftime("%Y-%m-%d"),
                                r["last"].strftime("%Y-%m-%d") if r["last"] else "",
                                r["source"],
                            )
                        )
                    print("")
                if sum([len(data[b]) for b in data]) == 0:
                    print("Nothing found")
            # ------------------------------ IP -------------------------------
            elif args.subcommand == "ip":
                if not is_ip(unbracket(args.IP)):
                    print("Invalid IP address")
                    sys.exit(1)
                data = {
                        "passive_dns": [],
                        "urls": [],
                        "malware": [],
                        "files": [],
                        "reports": [],
                        "ports": []
                }
                print("###################### %s ###################" % args.IP)
                for p in plugins:
                    if args.all:
                        if plugins[p].test_config(conf):
                            plugins[p].intel("ip", unbracket(args.IP), data, conf)
                    else:
                        if plugins[p].test_config(conf) and plugins[p].check_intel(conf):
                            plugins[p].intel("ip", unbracket(args.IP), data, conf)
                print("")

                if len(data["reports"]) > 0:
                    print("----------------- Intelligence Report")
                    for report in data["reports"]:
                        print("{} - {} - {} - {}".format(
                            report["date"].strftime("%Y-%m-%d") if report["date"] else "",
                            report["title"],
                            report["url"],
                            report["source"]
                        ))
                    print("")
                if len(data["malware"]) > 0:
                    print("----------------- Malware")
                    for r in data["malware"]:
                        print(
                            "[%s] %s %s"
                            % (
                                r["source"],
                                r["hash"],
                                r["date"].strftime("%Y-%m-%d") if r["date"] else "",
                            )
                        )
                    print("")
                if len(data["files"]) > 0:
                    print("----------------- Files")
                    for r in data["files"]:
                        if r["date"] != "":
                            print(
                                "[%s] %s (%s)"
                                % (
                                    r["source"],
                                    r["hash"],
                                    r["date"].strftime("%Y-%m-%d"),
                                )
                            )
                        else:
                            print(
                                "[%s] %s"
                                % (
                                    r["source"],
                                    r["hash"],
                                )
                            )
                    print("")
                if len(data["urls"]) > 0:
                    print("----------------- Urls")
                    for r in sorted(data["urls"], key=lambda x: x["date"], reverse=True):
                        print("{:9} {} - {} {}".format(
                                "[" + r["source"] + "]",
                                r["url"],
                                r["ip"],
                                r["date"].strftime("%Y-%m-%d"),
                            )
                        )
                    print("")
                if len(data["ports"]) > 0:
                    print("--------------------- Open Ports")
                    for p in data["ports"]:
                        print("{:6} - {} ({})".format(
                            p["port"],
                            p["info"],
                            p["source"]
                        ))
                    print("")
                if len(data["passive_dns"]) > 0:
                    print("----------------- Passive DNS")
                    for r in sorted(
                        data["passive_dns"], key=lambda x: x["first"], reverse=True
                    ):
                        print(
                            "[+] %-40s (%s -> %s)(%s)"
                            % (
                                r["domain"],
                                r["first"].strftime("%Y-%m-%d"),
                                r["last"].strftime("%Y-%m-%d") if r["last"] else "",
                                r["source"],
                            )
                        )
                    print("")
                if sum([len(data[b]) for b in data]) == 0:
                    print("Nothing found")
            elif args.subcommand == "hash":
                data = {
                        "samples": [],
                        "urls": [],
                        "network": [],
                        "reports": []
                }
                print("############### {}".format(args.HASH))
                for p in plugins:
                    if args.all:
                        if plugins[p].test_config(conf):
                            plugins[p].intel("hash", args.HASH, data, conf)
                    else:
                        if plugins[p].test_config(conf) and plugins[p].check_intel(conf):
                            plugins[p].intel("hash", args.HASH, data, conf)
                print("")

                if len(data["reports"]) > 0:
                    print("----------------- Intelligence Report")
                    for report in data["reports"]:
                        print("{} - {} - {} - {}".format(
                            report["date"].strftime("%Y-%m-%d") if report["date"] else "",
                            report["title"],
                            report["url"],
                            report["source"]
                        ))
                    print("")

                if len(data["samples"]) > 0:
                    print("----------------- Samples")
                    for sample in data["samples"]:
                        print("{} - {} {}".format(
                            sample["date"].strftime("%Y-%m-%d") if sample["date"] else "",
                            sample["source"],
                            sample["url"],
                        ))
                        if "infos" in sample:
                            for info in sample["infos"]:
                                print("- {} - {}".format(
                                    info,
                                    sample["infos"][info]
                                ))
                    print("")

                if len(data["network"]) > 0:
                    print("------------------ Network")
                    for host in data["network"]:
                        if "host2" in host:
                            print("{:30} {} - {}".format(
                                "{} ({})".format(host["host"], host["host2"]),
                                host["source"],
                                host["url"]
                            ))
                        else:
                            print("{:30} {} - {}".format(
                                host["host"],
                                host["source"],
                                host["url"]
                            ))
                    print("")

                if len(data["urls"]) > 0:
                    print("----------------- Urls")
                    for report in data["urls"]:
                        print("{} - {} - {}".format(
                            report["url"],
                            report["link"],
                            report["source"]
                        ))
                    print("")
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
