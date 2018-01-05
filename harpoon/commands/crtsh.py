#! /usr/bin/env python
import sys
import operator
import json
from harpoon.commands.base import Command
from harpoon.lib.utils import json_serial
from pycrtsh import Crtsh
from collections import Counter
from datetime import date, datetime


class CommandCert(Command):
    """
    # Crt.sh

    **Search and download information from https://crt.sh/

    * Search all certificates from a domain: `harpoon crtsh -d www.citizenlab.org`
    * Search all certificates from a list of domains in a file with CSV output: `harpoon crtsh -l FILE -f CSV`
    """
    name = "crtsh"
    description = "Search in https://crt.sh/ (Certificate Transparency database)"

    def add_arguments(self, parser):
        parser.add_argument('--domain', '-d', help='Search certificates for this domain and list shared alternate domains')
        parser.add_argument('--list', '-l', help='Search certificates for a list of domains in the given file')
        parser.add_argument('--format', '-f', choices=["csv", "json", "txt"], default="txt", help='Output format (default is txt)')
        self.parser = parser

    def run(self, conf, args, plugins):
        crt = Crtsh()
        if args.domain:
            index = crt.search(args.domain)
            if args.format == "txt":
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
            elif args.format == "json":
                certs = {}
                for c in index:
                    certs[c["id"]] = crt.get(c["id"], type="id")
                print(json.dumps(certs, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))
            elif args.format == "csv":
                print("id|serial|sha1|Common Name|Issuer|Not Before|Not After|Basic Constraints|Alt Names")
                for c in index:
                    data = crt.get(c["id"], type="id")
                    print("%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
                        c["id"],
                        data["serial"],
                        data["sha1"],
                        data["subject"]["commonName"],
                        data["issuer"]["commonName"],
                        data["not_before"],
                        data["not_after"],
                        data["extensions"]["basic_constraints"] if "basic_constraints" in data["extensions"] else "False",
                        ", ".join(data["extensions"]["alternative_names"]) if "alternative_names" in data["extensions"] else ""
                        )
                    )
        elif args.list:
            sha1_list = []
            with open(args.list, 'r') as f:
                domains = [a.strip() for a in f.read().split()]
            if args.format == "txt":
                for d in domains:
                    index = crt.search(d)
                    print("Certificates for %s" % d)
                    for c in index:
                        data = crt.get(c["id"], type="id")
                        print("%s\t%s\t%s\t%s" % (
                                data["subject"]["commonName"],
                                data["not_before"].isoformat(),
                                data["not_after"].isoformat(),
                                data["sha1"]
                            )
                        )
                    print("")
            elif args.format == "json":
                data = {}
                for d in domains:
                    data[d] = {}
                    index = crt.search(d)
                    for c in index:
                        if data["sha1"] not in sha1_list:
                            sha1_list.append(data["sha1"])
                            data[d][c["id"]] = crt.get(c["id"], type="id")
                print(json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))
            elif args.format == "csv":
                print("id|serial|sha1|Common Name|Issuer|Not Before|Not After|Basic Constraints|Alt Names")
                for d in domains:
                    index = crt.search(d)
                    for c in index:
                        data = crt.get(c["id"], type="id")
                        if data["sha1"] not in sha1_list:
                            sha1_list.append(data["sha1"])
                            print("%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
                                c["id"],
                                data["serial"],
                                data["sha1"],
                                data["subject"]["commonName"],
                                data["issuer"]["commonName"],
                                data["not_before"],
                                data["not_after"],
                                data["extensions"]["basic_constraints"] if "basic_constraints" in data["extensions"] else "False",
                                ", ".join(data["extensions"]["alternative_names"]) if "alternative_names" in data["extensions"] else ""
                                )
                            )
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()


