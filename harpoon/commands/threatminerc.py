#! /usr/bin/env python
import sys
import json
import datetime
import pytz
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket
from threatminer import ThreatMiner


class CommandThreatMiner(Command):
    """
    # ThreatMiner

    https://www.threatminer.org/

    * Get report related to an IOC : `harpoon threatminer report DOMAIN`
    * Get samples related to a domain or IP : `harpoon threatminer sample DOMAIN`
    * Get metadata of a file : `harpoon threatminer metadata HASH`
    * Get HTTP traffic for a file : `harpoon threatminer traffic HASH`
    * Get hosts associated with a file : `harpoon threatminer host HASH`
    * Get mutants associated with a file : `harpoon threatminer mutant HASH`
    * Get AV detections associated with a file : `harpoon threatminer av HASH`
    * Get whois info on a domain : `harpoon threatminer whois DOMAIN`
    * Get Passive DNS info on a domain : `harpoon threatminer dns DOMAIN`
    * Get URLs related to a domain : `harpoon threatminer uri DOMAIN`
    * Get subdomains related to a domain : `harpoon threatminer subdomain DOMAIN`
    """
    name = "threatminer"
    description = "Requests TreatMiner database https://www.threatminer.org/"
    config = {'ThreatMiner': []}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('report', help='Request information a Threat Report')
        parser_a.add_argument('INDICATOR', help='Indicator to check')
        parser_a.set_defaults(subcommand='report')
        parser_b = subparsers.add_parser('sample', help='Get samples associated with a domain or IP')
        parser_b.add_argument('INDICATOR', help='Indicator to check')
        parser_b.set_defaults(subcommand='sample')
        parser_c = subparsers.add_parser('metadata', help='Get metadata associated with a file')
        parser_c.add_argument('HASH', help='Hash to get metadata on')
        parser_c.set_defaults(subcommand='metadata')
        parser_d = subparsers.add_parser('traffic', help='Get HTTP traffic associated with a file')
        parser_d.add_argument('HASH', help='Hash to get metadata on')
        parser_d.set_defaults(subcommand='traffic')
        parser_e = subparsers.add_parser('host', help='Get hosts associated with a file')
        parser_e.add_argument('HASH', help='Hash to get info on')
        parser_e.set_defaults(subcommand='host')
        parser_f = subparsers.add_parser('mutant', help='Get mutants associated with a file')
        parser_f.add_argument('HASH', help='Hash to get info on')
        parser_f.set_defaults(subcommand='mutant')
        parser_g = subparsers.add_parser('av', help='Get AV detections associated with a file')
        parser_g.add_argument('HASH', help='Hash to get info on')
        parser_g.set_defaults(subcommand='av')
        parser_h = subparsers.add_parser('whois', help='Get whois info on a domain')
        parser_h.add_argument('DOMAIN', help='Domain')
        parser_h.set_defaults(subcommand='whois')
        parser_i = subparsers.add_parser('dns', help='Get Passive DNS info on a domain')
        parser_i.add_argument('DOMAIN', help='Domain')
        parser_i.set_defaults(subcommand='dns')
        parser_j = subparsers.add_parser('uri', help='Get URLs related to a domain')
        parser_j.add_argument('DOMAIN', help='Domain')
        parser_j.set_defaults(subcommand='uri')
        parser_k = subparsers.add_parser('subdomain', help='Get subdomains related to a domain')
        parser_k.add_argument('DOMAIN', help='Domain')
        parser_k.set_defaults(subcommand='subdomain')
        self.parser = parser


    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            tm = ThreatMiner()
            if args.subcommand == 'report':
                response = tm.get_report(unbracket(args.INDICATOR))
                if response['status_code'] == '200':
                    if len(response['results']) > 0:
                        print("Reports found:")
                        for r in response['results']:
                            print("{} {} - {}".format(
                                r['year'],
                                r['filename'],
                                r['URL']
                            ))
                    else:
                        print("No report found for this indicator")
                elif response['status_code'] == '404':
                    print("No report found for this indicator")
                else:
                    print("Request failed: {}".format(response['status_message']))
            elif args.subcommand == 'sample':
                response = tm.get_related_samples(unbracket(args.INDICATOR))
                if response['status_code'] == '200':
                    if len(response['results']) > 0:
                        print("Samples found:")
                        for r in response['results']:
                            print(r)
                    else:
                        print("No report found for this indicator")
                elif response['status_code'] == '404':
                    print("No report found for this indicator")
                else:
                    print("Request failed: {}".format(response['status_message']))
            elif args.subcommand == 'metadata':
                response = tm.get_metadata(args.HASH)
                if response['status_code'] == '200':
                    for r in response['results']:
                        for d in r:
                            print("{} - {}".format(d, r[d]))
                        print("")
                elif response['status_code'] == '404':
                    print("No report found for this indicator")
                else:
                    print("Request failed: {}".format(response['status_message']))
            elif args.subcommand == 'traffic':
                response = tm.get_http_traffic(args.HASH)
                if response['status_code'] == '200':
                    for t in response['results'][0]['http_traffic']:
                        for d in t.keys():
                            if d != 'raw':
                                print("{} - {}".format(d, t[d]))
                        print("")
                elif response['status_code'] == '404':
                    print("No traffic found for this file")
                else:
                    print("Request failed: {}".format(response['status_message']))
            elif args.subcommand == 'host':
                response = tm.get_hosts(args.HASH)
                if response['status_code'] == '200':
                    print("domains:")
                    for d in response["results"][0]["domains"]:
                        print("{} - {}".format(d["domain"], d["ip"]))
                    print("\nHosts:")
                    for h in response["results"][0]["hosts"]:
                        print(h)
                elif response['status_code'] == '404':
                    print("File not found")
                else:
                    print("Request failed: {}".format(response['status_message']))
            elif args.subcommand == 'mutant':
                response = tm.get_mutants(args.HASH)
                if response['status_code'] == '200':
                    for m in response["results"][0]['mutants']:
                        print(m)
                elif response['status_code'] == '404':
                    print("File not found")
                else:
                    print("Request failed: {}".format(response['status_message']))
            elif args.subcommand == 'av':
                response = tm.get_av_detections(args.HASH)
                if response['status_code'] == '200':
                    for m in response["results"][0]['av_detections']:
                        print(m)
                elif response['status_code'] == '404':
                    print("File not found")
                else:
                    print("Request failed: {}".format(response['status_message']))
            elif args.subcommand == 'whois':
                response = tm.who_is(args.DOMAIN)
                if response['status_code'] == '200':
                    print(json.dumps(response['results'][0]['whois'], indent=4))
                elif response['status_code'] == '404':
                    print("Domain not found")
                else:
                    print("Request failed: {}".format(response['status_message']))
            elif args.subcommand == 'dns':
                response = tm.passive_dns(args.DOMAIN)
                if response['status_code'] == '200':
                    for r in response['results']:
                        print("{} - {} - {}".format(
                            r["ip"] if "ip" in r else r["domain"],
                            r["first_seen"],
                            r["last_seen"]
                        ))
                elif response['status_code'] == '404':
                    print("Domain not found")
                else:
                    print("Request failed: {}".format(response['status_message']))
            elif args.subcommand == 'uri':
                response = tm.get_uris(args.DOMAIN)
                if response['status_code'] == '200':
                    print(json.dumps(response['results'][0]['whois'], indent=4))
                elif response['status_code'] == '404':
                    print("Domain not found")
                else:
                    print("Request failed: {}".format(response['status_message']))
            elif args.subcommand == 'subdomain':
                response = tm.get_subdomains(args.DOMAIN)
                if response['status_code'] == '200':
                    for s in response['results']:
                        print(s)
                elif response['status_code'] == '404':
                    print("Domain not found")
                else:
                    print("Request failed: {}".format(response['status_message']))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        if type == "domain":
            print("[+] Checking ThreatMiner...")
            tm = ThreatMiner()
            response = tm.passive_dns(query)
            if response['status_code'] == '200':
                for r in response['results']:
                    data["passive_dns"].append({
                        "ip": r["ip"],
                        "first": parse(r["first_seen"]).astimezone(pytz.utc),
                        "last": parse(r["last_seen"]).astimezone(pytz.utc),
                        "source": "ThreatMiner"
                    })
            response = tm.get_report(query)
            if response["status_code"] == "200":
                for r in response["results"]:
                    data["reports"].append({
                        "date": datetime.datetime(int(r["year"]), 1, 1),
                        "title": r["filename"],
                        "url": r["URL"],
                        "source": "ThreatMiner"
                    })
            else:
                print(
                    "Request to ThreatMiner failed: {}".format(
                        response["status_message"]
                    )
                )
            response = tm.get_related_samples(query)
            if response["status_code"] == "200":
                for r in response["results"]:
                    data["malware"].append(
                        {"hash": r, "date": None, "source": "ThreatMiner"}
                    )
        elif type == "ip":
            print("[+] Checking ThreatMiner...")
            tm = ThreatMiner()
            response = tm.passive_dns(query)
            if response['status_code'] == '200':
                for r in response['results']:
                    data["passive_dns"].append({
                        "domain": r["domain"],
                        "first": parse(r["first_seen"]).astimezone(pytz.utc),
                        "last": parse(r["last_seen"]).astimezone(pytz.utc),
                        "source": "ThreatMiner"
                    })
            response = tm.get_report(query)
            if response["status_code"] == "200":
                for r in response["results"]:
                    data["reports"].append({
                        "date": datetime.datetime(int(r["year"]), 1, 1),
                        "title": r["filename"],
                        "url": r["URL"],
                        "source": "ThreatMiner"
                    })
            response = tm.get_related_samples(query)
            if response["status_code"] == "200":
                for r in response["results"]:
                    data["malware"].append(
                        {"hash": r, "date": None, "source": "ThreatMiner"}
                    )
        elif type == "hash":
            print("[+] Checking ThreatMiner...")
            tm = ThreatMiner()
            response = tm.get_report(query)
            if response['status_code'] == '200':
                if len(response['results']) > 0:
                    for r in response['results']:
                        data["reports"].append({
                            "date": datetime.datetime(int(r["year"]), 1, 1),
                            "title": r["filename"],
                            "url": r["URL"],
                            "source": "ThreatMiner"
                        })
