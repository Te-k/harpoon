#! /usr/bin/env python
import json

from pycrtsh import Crtsh, CrtshCertificateNotFound

from harpoon.commands.base import Command, Subcommand
from harpoon.lib.utils import unbracket


class SubcommandCert(Subcommand):
    description = "Show details for a certificate"
    cmd = "cert"

    def add_arguments(self, parser):
        parser = parser.add_argument('ID', help='ID, sha1 or sha256 of a certificate')

    def run(self, args):
        crt = Crtsh()
        try:
            if len(args.ID) == 64:
                self.data = crt.get(args.ID, type="sha256")
            elif len(args.ID) == 40:
                self.data = crt.get(args.ID, type="sha1")
            else:
                self.data = crt.get(args.ID, type="id")
        except CrtshCertificateNotFound:
            self.data = None

    def display(self, args):
        if self.data:
            print(json.dumps(self.data, indent=4, default=str))
        else:
            print("Certificate not found")


class SubcommandDomain(Subcommand):
    # TODO: implement in depth list
    description = "Get certificates of a domain"
    cmd = "domain"

    def add_arguments(self, parser):
        parser.add_argument('DOMAIN', help='Domain')
        parser.add_argument(
            '--format', '-f',
            choices=["csv", "json", "txt"],
            default="txt",
            help='Output format (default is txt)'
        )

    def run(self, args):
        crt = Crtsh()
        self.data = crt.search(unbracket(args.DOMAIN))

    def display(self, args):
        if args.format == "txt":
            print("Certificates")
            for c in self.data:
                print("%s\t%s\t%s\t%s" % (
                    c["name"],
                    c["not_before"].isoformat(),
                    c["not_after"].isoformat(),
                    c["id"]
                    )
                )
        elif args.format == "json":
            print(json.dumps(self.data, indent=4, default=str))
        else:
            print("id|name|Issuer|Not Before|Not After")
            for c in self.data:
                print("{}|{}|{}|{}|{}".format(
                    c["id"],
                    c["name"],
                    ", ".join(["{}={}".format(a, b) for (a, b) in c["ca"]["parsed_name"].items()]),
                    c["not_before"],
                    c["not_after"],
                    )
                )


class SubcommandList(Subcommand):
    description = "Get certificates for a list of domains"
    cmd = "list"

    def add_arguments(self, parser):
        parser.add_argument('FILE', help='File containing a list of domains')
        parser.add_argument(
            '--format', '-f',
            choices=["csv", "json", "txt"],
            default="txt",
            help='Output format (default is txt)'
        )

    def run(self, args):
        crt = Crtsh()

        # Get the list of domains
        with open(args.FILE, 'r') as f:
            domains = [a.strip() for a in f.read().split()]

        # Get certificates
        self.data = []
        for d in domains:
            self.data.extend(crt.search(d))

    def display(self, args):
        if args.format == "txt":
            print("Certificates")
            for c in self.data:
                print("%s\t%s\t%s\t%s" % (
                    c["name"],
                    c["not_before"].isoformat(),
                    c["not_after"].isoformat(),
                    c["id"]
                    )
                )
        elif args.format == "json":
            print(json.dumps(self.data, indent=4, default=str))
        else:
            print("id|name|Issuer|Not Before|Not After")
            for c in self.data:
                print("{}|{}|{}|{}|{}".format(
                    c["id"],
                    c["name"],
                    ", ".join(["{}={}".format(a, b) for (a, b) in c["ca"]["parsed_name"].items()]),
                    c["not_before"],
                    c["not_after"],
                    )
                )


class SubcommandSubdomains(Subcommand):
    description = "Search subdomains of a domain through certificates"
    cmd = "subdomains"

    def add_arguments(self, parser):
        parser.add_argument('DOMAIN', help='Domain')

    def run(self, args):
        crt = Crtsh()
        subdomains = set()
        index = crt.search(unbracket(args.DOMAIN))
        for c in index:
            data = crt.get(c["id"], type="id")
            subdomains.add(data["subject"]["commonName"])
            if "alternative_names" in data["extensions"]:
                for d in data["extensions"]["alternative_names"]:
                    subdomains.add(d)
        self.data = list(subdomains)

    def display(self, args):
        for d in self.data:
            print(d)


class CommandCertsh(Command):
    """
    # Crt.sh

    **Search and download information from https://crt.sh/

    * Search all certificates from a domain: `harpoon crtsh domain amnesty.org`
    * Search all certificates from a list of domains in a file with CSV output: `harpoon crtsh list FILE -f CSV`
    * Search for subdomains of a domain : `harpoon crtsh subdomains DOMAIN`
    * Show details of a certificate : `harpoon crtsh cert SHA1`
    """
    name = "crtsh"
    description = "Search in https://crt.sh/ (Certificate Transparency database)"
    config = {'Crtsh': []}

    def __init__(self, config):
        super().__init__(config=config)
        self.add_subcommand(SubcommandCert)
        self.add_subcommand(SubcommandDomain)
        self.add_subcommand(SubcommandList)
        self.add_subcommand(SubcommandSubdomains)

    def intel_domain(self, query, data):
        print("[+] Checking Crtsh...")
        crt = Crtsh()
        subdomains = set()
        index = crt.search(unbracket(query))
        for c in index:
            data = crt.get(c["id"], type="id")
            subdomains.add(data["subject"]["commonName"])
            if "alternative_names" in data["extensions"]:
                for d in data["extensions"]["alternative_names"]:
                    data["subdomains"].add(d)
