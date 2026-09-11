#! /usr/bin/env python
from .base import HarpoonPlugin


class IntelSubcommand:
    """
    Class to handle common display format
    """

    def print_threat_report(self):
        if len(self.results["reports"]) > 0:
            print("----------------- Intelligence Report")
            for report in self.results["reports"]:
                print(
                    "{} - {} - {} - {}".format(
                        report["date"].strftime("%Y-%m-%d") if report["date"] else "",
                        report["title"],
                        report["url"],
                        report["source"],
                    )
                )
            print("")

    def print_passive_dns(self):
        passive_dns = self.results["passive_dns"]
        if len(passive_dns) > 0:
            print("----------------- Passive DNS")
            for r in sorted(passive_dns, key=lambda x: x["first"], reverse=True):
                print(
                    "[+] %-40s (%s -> %s)(%s)"
                    % (
                        r["ip"] if "ip" in r else r["domain"],
                        r["first"].strftime("%Y-%m-%d"),
                        r["last"].strftime("%Y-%m-%d") if r["last"] else "",
                        r["source"],
                    )
                )
            print("")

    def print_urls(self):
        if len(self.results["urls"]) > 0:
            print("----------------- Urls")
            for r in sorted(
                self.results["urls"], key=lambda x: x["date"], reverse=True
            ):
                print(
                    "{:9} {} - {} {}".format(
                        "[" + r["source"] + "]",
                        r["url"],
                        r["ip"],
                        r["date"].strftime("%Y-%m-%d"),
                    )
                )
            print("")


class IntelIp(HarpoonPlugin, IntelSubcommand):
    name = "ip"
    description = "Gather intelligence on an IP address"

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.parser.add_argument("IP", help="IP address")

    def fetch(self):
        # Only passive DNS for now
        self.results = {}
        self.results["passive_dns"] = []
        self.results["reports"] = []
        self.results["urls"] = []
        for plugin in self.plugins:
            if not self.plugins[plugin].is_config_valid():
                continue
            if not self.plugins[plugin].is_intel_enabled():
                continue

            try:
                self.plugins[plugin].intel_ip(self.unbracket(self.args.IP))
                print(
                    "Downloaded {} information".format(
                        self.plugins[plugin].__class__.__name__
                    )
                )
                self.results["passive_dns"].extend(self.plugins[plugin].passive_dns)
                self.results["reports"].extend(self.plugins[plugin].reports)
                self.results["urls"].extend(self.plugins[plugin].urls)

            except NotImplementedError:
                pass

    def display_txt(self):
        self.print_threat_report()
        self.print_passive_dns()
        self.print_urls()


class IntelDomain(HarpoonPlugin, IntelSubcommand):
    name = "domain"
    description = "Gather intelligence on a domain"

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.parser.add_argument("DOMAIN", help="Domain name")

    def fetch(self):
        self.results = {}
        self.results["passive_dns"] = []
        self.results["reports"] = []
        self.results["urls"] = []
        for plugin in self.plugins:
            if not self.plugins[plugin].is_config_valid():
                continue
            if not self.plugins[plugin].is_intel_enabled():
                continue

            try:
                self.plugins[plugin].intel_domain(self.unbracket(self.args.DOMAIN))
                print(
                    "Downloaded {} information".format(
                        self.plugins[plugin].__class__.__name__
                    )
                )
                self.results["passive_dns"].extend(self.plugins[plugin].passive_dns)
                self.results["reports"].extend(self.plugins[plugin].reports)
                self.results["urls"].extend(self.plugins[plugin].urls)
            except NotImplementedError:
                pass

    def display_txt(self):
        self.print_threat_report()
        self.print_passive_dns()
        self.print_urls()


class Intel(HarpoonPlugin):
    """
    # Intel

    Gather information from multiple Threat Intelligence platforms

    * **harpoon intel domain DOMAIN**
    * **harpoon intel ip IP**
    """

    name = "intel"
    description = "Gather intelligence over an IP or Domain"

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.add_subcommand(IntelIp)
        self.add_subcommand(IntelDomain)
