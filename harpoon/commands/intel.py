#! /usr/bin/env python
import os
import sys
import traceback

from harpoon.commands.base import Command
from harpoon.lib.utils import is_ip, unbracket


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
    geoasn = os.path.join(os.path.expanduser(
        "~"), ".config/harpoon/GeoLite2-ASN.mmdb")
    asnname = os.path.join(os.path.expanduser(
        "~"), ".config/harpoon/asnnames.csv")
    asncidr = os.path.join(os.path.expanduser(
        "~"), ".config/harpoon/asncidr.dat")

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

        parser_d = subparsers.add_parser(
            "email", help="Gather Threat Intelligence information on an email address"
        )
        parser_d.add_argument("EMAIL", help="Email address")
        parser_d.add_argument("--all", "-a", action="store_true",
                              help="Query all plugins configured and available")
        parser_d.set_defaults(subcommand="email")
        # parser_d = subparsers.add_parser(
        # "subdomain", help="Gather Threat Intelligence information on subdomains of a given domain"
        # )

        self.parser = parser

    def print_threat_report(self, reports):
        if len(reports) > 0:
            print("----------------- Intelligence Report")
            for report in reports:
                print("{} - {} - {} - {}".format(
                    report["date"].strftime(
                        "%Y-%m-%d") if report["date"] else "",
                    report["title"],
                    report["url"],
                    report["source"]
                ))
            print("")

    def print_passive_dns(self, passive_dns, domain=True):
        if len(passive_dns) > 0:
            print("----------------- Passive DNS")
            for r in sorted(passive_dns, key=lambda x: x["first"], reverse=True):
                if domain:
                    el = r["domain"]
                else:
                    el = r["ip"]
                print(
                    "[+] %-40s (%s -> %s)(%s)"
                    % (
                        el,
                        r["first"].strftime("%Y-%m-%d"),
                        r["last"].strftime(
                            "%Y-%m-%d") if r["last"] else "",
                        r["source"],
                    )
                )
            print("")

    def print_malware(self, malware):
        if len(malware) > 0:
            print("----------------- Malware")
            for r in malware:
                print(
                    "[%s] %s %s"
                    % (
                        r["source"],
                        r["hash"],
                        r["date"].strftime(
                            "%Y-%m-%d") if r["date"] else "",
                    )
                )
            print("")

    def print_files(self, files):
        if len(files) > 0:
            print("----------------- Files")
            for r in files:
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

    def print_urls(self, urls):
        if len(urls) > 0:
            print("----------------- Urls")
            for r in sorted(urls, key=lambda x: x["date"], reverse=True):
                print("{:9} {} - {} {}".format(
                    "[" + r["source"] + "]",
                    r["url"],
                    r["ip"],
                    r["date"].strftime("%Y-%m-%d"),
                ))
            print("")

    def do_intel_domain(self, domain, args, plugins):
        data = {
            "passive_dns": [],
            "urls": [],
            "malware": [],
            "files": [],
            "reports": [],
            "subdomains": []
        }
        print("###################### %s ###################" % domain)
        for p in plugins:
            try:
                if args.all:
                    if plugins[p].test_config():
                        plugins[p].intel(
                                "domain",
                                domain,
                                data)
                else:
                    if plugins[p].test_config() and plugins[p].check_intel():
                        plugins[p].intel(
                            "domain",
                            domain,
                            data
                        )
            except Exception:
                print("Command {} failed".format(p))
                traceback.print_exc()
        print("")

        self.print_threat_report(data["reports"])
        self.print_malware(data["malware"])
        self.print_files(data["files"])
        self.print_urls(data["urls"])
        self.print_passive_dns(data["passive_dns"], domain=False)

        if len(data['subdomains']) > 0:
            print('-------------------- Subdomains')
            for r in data['subdomains']:
                print(
                    "[%s] %s" % (r['source'], r['domain'])
                )

        if sum([len(data[b]) for b in data]) == 0:
            print("Nothing found")

    def do_intel_ip(self, ip, args, plugins):
        """
        Check intel on an IP address using other plugins
        """
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
            try:
                if args.all:
                    if plugins[p].test_config():
                        plugins[p].intel(
                            "ip",
                            ip,
                            data
                        )
                else:
                    if plugins[p].test_config() and plugins[p].check_intel():
                        plugins[p].intel(
                            "ip",
                            ip,
                            data
                        )
            except Exception:
                print("Command {} failed".format(p))
                traceback.print_exc()
        print("")

        self.print_threat_report(data["reports"])
        self.print_malware(data["malware"])
        self.print_files(data["files"])
        self.print_urls(data["urls"])
        self.print_passive_dns(data["passive_dns"])

        if len(data["ports"]) > 0:
            print("--------------------- Open Ports")
            for p in data["ports"]:
                print("{:6} - {} ({})".format(
                    p["port"],
                    p["info"],
                    p["source"]
                ))
            print("")

        if sum([len(data[b]) for b in data]) == 0:
            print("Nothing found")

    def do_intel_hash(self, hash_, args, plugins):
        """
        Query a hash to all plugins
        """
        data = {
            "samples": [],
            "urls": [],
            "network": [],
            "reports": []
        }
        print("############### {}".format(hash_))
        for p in plugins:
            try:
                if args.all:
                    if plugins[p].test_config():
                        plugins[p].intel("hash", hash_, data)
                else:
                    if plugins[p].test_config() and plugins[p].check_intel():
                        plugins[p].intel("hash", hash_, data)
            except Exception:
                print("Command {} failed".format(p))
                traceback.print_exc()
        print("")

        self.print_threat_report(data["reports"])

        if len(data["samples"]) > 0:
            print("----------------- Samples")
            for sample in data["samples"]:
                print("{} - {} {}".format(
                    sample["date"].strftime(
                        "%Y-%m-%d") if sample["date"] else "",
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

        if sum([len(data[b]) for b in data]) == 0:
            print("Nothing found")

    def do_intel_email(self, email, args, plugins):
        """
        Query intel on emails
        """
        data = {
            "domains": [],
            "keys": [],
            "mentions": [],
            # "samples": [],
            # "urls": [],
            # "reports": []
        }

        print("############### {}".format(email))
        for p in plugins:
            try:
                if args.all:
                    if plugins[p].test_config():
                        plugins[p].intel("email", email, data)
                else:
                    if plugins[p].test_config() and plugins[p].check_intel():
                        plugins[p].intel("email", email, data)
            except Exception:
                print("Command {} failed".format(p))
                traceback.print_exc()
        print("")

        # Print domains
        if len(data["domains"]) > 0:
            print("----------------- Domains")
            for d in data["domains"]:
                print("[%s] %-25s (%s)" % (
                    d["registered"],
                    d["domain"],
                    ', '.join(d["infos"])
                ))

        # Print keys
        if len(data["keys"]) > 0:
            print("----------------- Keys")
            # TODO: sort by date
            for k in data["keys"]:
                print("[+] %s\t%s\t%s %s" % (
                    k['id'],
                    k['date'].strftime("%Y-%m-%d"),
                    k['name'],
                    k['email']
                ))

        # Print mentions
        if len(data["mentions"]) > 0:
            print("----------------- Mentions")
            for page in data["mentions"]:
                print("[{}] {}".format(
                    page["source"],
                    page["url"]
                ))

        if sum([len(data[b]) for b in data]) == 0:
            print("Nothing found")

    def run(self, args, plugins):
        if "subcommand" in args:
            if args.subcommand == "domain":
                self.do_intel_domain(unbracket(args.DOMAIN), args, plugins)
            elif args.subcommand == "ip":
                if not is_ip(unbracket(args.IP)):
                    print("Invalid IP address")
                    sys.exit(1)
                self.do_intel_ip(unbracket(args.IP), args, plugins)
            elif args.subcommand == "hash":
                # TODO : check hash format
                self.do_intel_hash(args.HASH, args, plugins)
            elif args.subcommand == "email":
                self.do_intel_email(args.EMAIL, args, plugins)
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
