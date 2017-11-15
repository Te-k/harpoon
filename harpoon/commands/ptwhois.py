#! /usr/bin/env python
import sys
import json
import datetime
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket
from passivetotal.libs.whois import WhoisRequest

class CommandPtWhois(Command):
    name = "ptwhois"
    description = "Requests Passive Total whois information"
    config = {'PassiveTotal': ['username', 'key']}

    def add_arguments(self, parser):
        self.parser = parser
        parser.add_argument('--domain', '-d', help='DOMAIN to be queried')
        parser.add_argument('--file', '-f', help='File with list of domains')


    def run(self, conf, args):
        if 'PassiveTotal' not in conf:
            print("Bad configuration, quitting...")
            sys.exit(1)
        if "username" not in conf['PassiveTotal'] or "key" not in conf['PassiveTotal']:
            print("Bad configuration, quitting...")
            sys.exit(1)
        client = WhoisRequest(conf['PassiveTotal']['username'], conf['PassiveTotal']['key'])
        if args.domain:
            raw_results = client.search_whois_by_field(
                query=unbracket(args.domain.strip()),
                field="domain"
            )
            print(json.dumps(raw_results,  sort_keys=True, indent=4, separators=(',', ': ')))
        elif args.file:
            with open(args.file, 'r') as infile:
                data = infile.read().split()
            print("Domain|Date|Registrar|name|email|Phone|organization|Street|City|Postal Code|State|Country")
            for d in data:
                do = unbracket(d.strip())
                raw_results = client.search_whois_by_field(
                    query=do,
                    field="domain"
                )
                if "results" not in raw_results:
                    print("%s|||||||||||" %  bracket(do) )
                else:
                    if len(raw_results["results"]) == 0:
                        print("%s|||||||||||" %  bracket(do) )
                    else:
                        r = raw_results["results"][0]
                        if "registered" in r:
                            dd = datetime.datetime.strptime(r["registered"], "%Y-%m-%dT%H:%M:%S.%f%z")
                            ddo = dd.strftime("%m/%d/%Y %H:%M:%S")
                        else:
                            ddo = ""

                        print("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
                                bracket(do),
                                ddo,
                                r["registrar"] if "registrar" in r else "",
                                r["registrant"]["name"] if "name" in r["registrant"] else "",
                                r["registrant"]["email"] if "email" in r["registrant"] else "",
                                r["registrant"]["telephone"] if "telephone" in r["registrant"] else "",
                                r["registrant"]["organization"] if "organization" in r["registrant"] else "",
                                r["registrant"]["street"] if "street" in r["registrant"] else "",
                                r["registrant"]["city"] if "city" in r["registrant"] else "",
                                r["registrant"]["postalCode"] if "postalCode" in r["registrant"] else "",
                                r["registrant"]["state"] if "state" in r["registrant"] else "",
                                r["registrant"]["country"] if "country" in r["registrant"] else ""
                            )
                        )
        else:
            self.parser.print_help()
