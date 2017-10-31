#! /usr/bin/env python
import sys
import operator
from harpoon.commands.base import Command
from pycrtsh import Crtsh
from collections import Counter

class CommandCert(Command):
    name = "cert"
    description = "Request certificate information"

    def add_arguments(self, parser):
        parser.add_argument('--domain', '-d', help='Search certificates for this domain and list shared alternate domains')
        self.parser = parser

    def run(self, conf, args):
        crt = Crtsh()
        if args.domain:
            index = crt.search(args.domain)
            domains = []
            print("Certificates")
            for c in index:
                data = crt.get(c["id"], type="id")
                print("%s\t%s\t%s\t%s" % (
                    data["subject"]["commonName"],
                    data["not_before"].isoformat(),
                    data["not_after"].isoformat(),
                    data["sha1"]
                    )
                )
                if "alternative_names" in data["extensions"]:
                    domains += list(set([a[2:] if a.startswith("*.") else a for a in data["extensions"]["alternative_names"]]))

            print("\nDomains")
            count = Counter(domains)
            for d in sorted(count.items(), key=operator.itemgetter(1), reverse=True):
                print("-%s: %i occurences" % (d[0], d[1]))
        else:
            self.parser.print_help()


