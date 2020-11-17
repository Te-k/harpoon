#! /usr/bin/env python
import sys
import json
import datetime
import pytz
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket
from passivetotal.libs.whois import WhoisRequest
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.enrichment import EnrichmentRequest


class CommandPassiveTotal(Command):
    """
    # Passive Total

    * Get a domain whois: `harpoon pt whois -d example.org`
    * Search for a domain registered by an email address: `harpoon pt whois -e admin@example.org`
    * Get whois information for a domain list in a file: `harpoon pt whois -f FILE`
    * Query DNS information for a domain: `harpoon pt dns example.org`
    * Check malware related to a domain: `harpoon pt malware -d example.org`
    * Check report related to a domain: `harpoon pt osint -d example.org`
    """
    name = "pt"
    description = "Requests Passive Total database"
    config = {'PassiveTotal': ['username', 'key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('whois', help='Request whois info')
        parser_a.add_argument('--domain', '-d', help='DOMAIN to be queried')
        parser_a.add_argument('--file', '-f', help='File with list of domains')
        parser_a.add_argument('--email', '-e', help='Check for domain registered by this email')
        parser_a.set_defaults(subcommand='whois')
        parser_b = subparsers.add_parser('dns', help='Request dns info')
        parser_b.add_argument('DOMAIN',  help='DOMAIN to be queried')
        parser_b.set_defaults(subcommand='dns')
        parser_c = subparsers.add_parser('malware', help='Request malware info')
        parser_c.add_argument('--domain', '-d',  help='DOMAIN to be queried')
        parser_c.add_argument('--file', '-f',  help='Check malware info from a domain list in a file and return csv of results')
        parser_c.add_argument('--raw', '-r',  help='Show raw results (JSON)', action="store_true")
        parser_c.set_defaults(subcommand='malware')
        parser_d = subparsers.add_parser('osint', help='Request OSINT info')
        parser_d.add_argument('--domain', '-d',  help='DOMAIN to be queried')
        parser_d.add_argument('--file', '-f',  help='Check OSINT info from a domain list in a file and return csv of results')
        parser_d.add_argument('--raw', '-r',  help='Show raw results (JSON)', action="store_true")
        parser_d.set_defaults(subcommand='osint')
        self.parser = parser


    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            if args.subcommand == 'whois':
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
                        # FIXME: bulk request here
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


                elif args.email:
                    raw_results = client.search_whois_by_field(
                        query=args.email.strip(),
                        field="email"
                    )
                    print(json.dumps(raw_results,  sort_keys=True, indent=4, separators=(',', ': ')))
                else:
                    self.parser.print_help()
            elif args.subcommand == "dns":
                client = DnsRequest(conf['PassiveTotal']['username'], conf['PassiveTotal']['key'])
                raw_results = client.get_passive_dns(
                    query=unbracket(args.DOMAIN),
                )
                print(json.dumps(raw_results,  sort_keys=True, indent=4, separators=(',', ': ')))
            elif args.subcommand == "malware":
                client = EnrichmentRequest(conf["PassiveTotal"]["username"], conf["PassiveTotal"]['key'])
                if args.domain:
                    raw_results = client.get_malware(query=args.domain)
                    print(json.dumps(raw_results,  sort_keys=True, indent=4, separators=(',', ': ')))
                elif args.file:
                    with open(args.file, 'r') as infile:
                        data = infile.read().split()
                    domain_list = list(set([a.strip() for a in data]))
                    if len(domain_list) < 51:
                        raw_results = client.get_bulk_malware(query=domain_list)
                        if "results" not in raw_results or not raw_results["success"]:
                            print("Request failed")
                            print(json.dumps(raw_results,  sort_keys=True, indent=4, separators=(',', ': ')))
                            sys.exit(1)
                        else:
                            results = raw_results["results"]
                    else:
                        results = {}
                        bulk_size=50
                        i = 0
                        while i*bulk_size < len(domain_list):
                            raw_results = client.get_bulk_malware(query=domain_list[i*bulk_size:(i+1)*bulk_size])
                            if "results" not in raw_results or not raw_results["success"]:
                                print("Request failed")
                                print(json.dumps(raw_results,  sort_keys=True, indent=4, separators=(',', ': ')))
                                sys.exit(1)
                            else:
                                results.update(raw_results["results"])
                            i += 1
                    if args.raw:
                        print(json.dumps(results, sort_keys=True, indent=4, separators=(',', ': ')))
                    else:
                        print("Domain|Date|Sample|Source|Source URL")
                        for domain in results:
                            if "results" in results[domain]:
                                for sample in results[domain]["results"]:
                                    print("%s|%s|%s|%s|%s" % (
                                                domain,
                                                sample["collectionDate"],
                                                sample["sample"],
                                                sample["source"],
                                                sample["sourceUrl"]
                                            )
                                        )

                else:
                    self.parser.print_help()

            elif args.subcommand == "osint":
                # FIXME: add research of projects
                client = EnrichmentRequest(conf["PassiveTotal"]["username"], conf["PassiveTotal"]['key'])
                if args.domain:
                    raw_results = client.get_osint(query=args.domain)
                    print(json.dumps(raw_results,  sort_keys=True, indent=4, separators=(',', ': ')))
                elif args.file:
                    with open(args.file, 'r') as infile:
                        data = infile.read().split()
                    domain_list = list(set([a.strip() for a in data]))
                    if len(domain_list) < 51:
                        raw_results = client.get_bulk_osint(query=domain_list)
                        if "results" not in raw_results or not raw_results["success"]:
                            print("Request failed")
                            print(json.dumps(raw_results,  sort_keys=True, indent=4, separators=(',', ': ')))
                            sys.exit(1)
                        else:
                            results = raw_results["results"]
                    else:
                        results = {}
                        bulk_size=50
                        i = 0
                        while i*bulk_size < len(domain_list):
                            raw_results = client.get_bulk_osint(query=domain_list[i*bulk_size:(i+1)*bulk_size])
                            if "results" not in raw_results or not raw_results["success"]:
                                print("Request failed")
                                print(json.dumps(raw_results,  sort_keys=True, indent=4, separators=(',', ': ')))
                                sys.exit(1)
                            else:
                                results.update(raw_results["results"])
                            i += 1
                    if args.raw:
                        print(json.dumps(results, sort_keys=True, indent=4, separators=(',', ': ')))
                    else:
                        print("Domain|Source|URL|Tags")
                        for domain in results:
                            if "results" in results[domain]:
                                for report in results[domain]["results"]:
                                    print("%s|%s|%s|%s" % (
                                            domain,
                                            report["source"],
                                            report["source_url"],
                                            " / ".join(report["tags"])
                                        )
                                    )
                else:
                    self.parser.print_help()

            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        if type == "domain":
            print("[+] Checking Passive Total...")
            try:
                pt_osint = {}
                ptout = False
                client = DnsRequest(
                    conf["PassiveTotal"]["username"],
                    conf["PassiveTotal"]["key"],
                )
                raw_results = client.get_passive_dns(query=query)
                if "results" in raw_results:
                    for res in raw_results["results"]:
                        data["passive_dns"].append(
                            {
                                "first": parse(res["firstSeen"]).astimezone(
                                    pytz.utc
                                ),
                                "last": parse(res["lastSeen"]).astimezone(
                                    pytz.utc
                                ),
                                "ip": res["resolve"],
                                "source": "PT",
                            }
                        )
                if "message" in raw_results:
                    if "quota_exceeded" in raw_results["message"]:
                        print("PT quota exceeded")
                        ptout = True
                if not ptout:
                    client2 = EnrichmentRequest(
                        conf["PassiveTotal"]["username"],
                        conf["PassiveTotal"]["key"],
                    )
                    # Get OSINT
                    pt_osint = client2.get_osint(query=query)
                    if "results" in pt_osint:
                        for r in pt_osint["results"]:
                            data["reports"].append({
                                "date": "",
                                "title": r["name"] if "name" in r else "",
                                "url": r["sourceUrl"],
                                "source": "PT"
                            })
                    # Get malware
                    raw_results = client2.get_malware(
                        query=query
                    )
                    if "results" in raw_results:
                        for r in raw_results["results"]:
                            data["malware"].append(
                                {
                                    "hash": r["sample"],
                                    "date": parse(
                                        r["collectionDate"]
                                    ).astimezone(pytz.utc),
                                    "source": "PT (%s)" % r["source"],
                                }
                            )
            except requests.exceptions.ReadTimeout:
                print("PT: Time Out")
        elif type == "ip":
            print("[+] Checking Passive Total...")
            try:
                pt_osint = {}
                ptout = False
                client = DnsRequest(
                    conf["PassiveTotal"]["username"],
                    conf["PassiveTotal"]["key"],
                )
                raw_results = client.get_passive_dns(query=query)
                if "results" in raw_results:
                    for res in raw_results["results"]:
                        data["passive_dns"].append(
                            {
                                "first": parse(res["firstSeen"]).astimezone(
                                    pytz.utc
                                ),
                                "last": parse(res["lastSeen"]).astimezone(
                                    pytz.utc
                                ),
                                "domain": res["resolve"],
                                "source": "PT",
                            }
                        )
                if "message" in raw_results:
                    if "quota_exceeded" in raw_results["message"]:
                        print("PT quota exceeded")
                        ptout = True
                if not ptout:
                    client2 = EnrichmentRequest(
                        conf["PassiveTotal"]["username"],
                        conf["PassiveTotal"]["key"],
                    )
                    # Get OSINT
                    pt_osint = client2.get_osint(query=query)
                    if "results" in pt_osint:
                        for r in pt_osint["results"]:
                            data["reports"].append({
                                "date": "",
                                "title": r["name"] if "name" in r else "",
                                "url": r["sourceUrl"],
                                "source": "PT"
                            })
                    # Get malware
                    raw_results = client2.get_malware(
                        query=query
                    )
                    if "results" in raw_results:
                        for r in raw_results["results"]:
                            data["malware"].append(
                                {
                                    "hash": r["sample"],
                                    "date": parse(
                                        r["collectionDate"]
                                    ).astimezone(pytz.utc),
                                    "source": "PT (%s)" % r["source"],
                                }
                            )
            except requests.exceptions.ReadTimeout:
                print("PT: Time Out")
