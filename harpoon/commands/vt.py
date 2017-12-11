#! /usr/bin/env python
import sys
import json
from harpoon.commands.base import Command
from virus_total_apis import PublicApi, PrivateApi


class CommandVirusTotal(Command):
    name = "vt"
    description = "Request Virus Total API"
    config = {'VirusTotal': ['key', 'type']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('hash', help='Request info on a hash')
        parser_a.add_argument('HASH', help='Hash')
        parser_a.add_argument('--raw', '-r', help='Raw data', action='store_true')
        parser_a.add_argument('--extended', '-e', help='Extended info (private API only)', action='store_true')
        parser_a.set_defaults(subcommand='hash')
        parser_b = subparsers.add_parser('hashlist', help='Request a list of hashes')
        parser_b.add_argument('FILE',  help='File containing the domains')
        parser_b.set_defaults(subcommand='hashlist')
        parser_c = subparsers.add_parser('domain', help='Request info on a domain')
        parser_c.add_argument('DOMAIN',  help='Domain')
        parser_c.add_argument('--json', '-j', action='store_true', help='Show raw JSON info')
        parser_c.set_defaults(subcommand='domain')
        parser_d = subparsers.add_parser('ip', help='Request info on an IP')
        parser_d.add_argument('IP',  help='IP')
        parser_d.set_defaults(subcommand='ip')
        parser_e = subparsers.add_parser('url', help='Request info on an URL')
        parser_e.add_argument('URL',  help='URL')
        parser_e.set_defaults(subcommand='url')
        parser_f = subparsers.add_parser('domainlist', help='Request info on a list of domains')
        parser_f.add_argument('FILE',  help='File containing the list of domains')
        parser_f.set_defaults(subcommand='domainlist')
        self.parser = parser
        self.parser = parser

    def print_domaininfo(self, res):
        """Print nicely the domain information"""
        if "results" in res:
            if "verbose_msg" in res["results"]:
                print(res["results"]["verbose_msg"])
            if "detected_urls" in res["results"]:
                if len(res["results"]["detected_urls"]) > 0:
                    print("-Detected urls:")
                    for r in res["results"]["detected_urls"]:
                        print("\t%s (on %s, %i/%i)" % (
                                r["url"],
                                r["scan_date"],
                                r["positives"],
                                r["total"]
                            )
                        )
            if "undetected_urls" in res["results"]:
                print("-Undetected urls:")
                for r in res["results"]["undetected_urls"]:
                    print("\t%s (on %s, %i/%i)" % (
                            r[0],
                            r[4],
                            r[2],
                            r[3]
                        )
                    )
            if "resolutions" in res["results"]:
                if len(res["results"]["resolutions"]) > 0:
                    print("-Resolutions:")
                    for r in res["results"]["resolutions"]:
                        print("\t%s (%s)" % (r["ip_address"], r["last_resolved"]))
            if "detected_referrer_samples" in res["results"]:
                if len(res["results"]["detected_referrer_samples"]) > 0:
                    print("-Detected Referrer Sample:")
                    for r in res["results"]["detected_referrer_samples"]:
                        print("\t%s (%i/%i)" % (
                                r["sha256"],
                                r["positives"],
                                r["total"]
                            )
                        )
            if "undetected_referrer_samples" in res["results"]:
                if len(res["results"]["undetected_referrer_samples"]) > 0:
                    print("-Undetected Referrer Sample:")
                    for r in res["results"]["undetected_referrer_samples"]:
                        print("\t%s (%i/%i)" (
                                r["sha256"],
                                r["positives"],
                                r["total"]
                            )
                        )
            if "undetected_downloaded_samples" in res["results"]:
                if len(res["results"]["undetected_downloaded_samples"]) > 0:
                    print("-Undetected Downloaded Sample:")
                    for r in res["results"]["undetected_downloaded_samples"]:
                        print("\t%s (on %s, %i/%i)" % (
                                r["sha256"],
                                r["date"],
                                r["positives"],
                                r["total"]
                            )
                        )
            if "detected_downloaded_samples" in res["results"]:
                if len(res["results"]["detected_downloaded_samples"]) > 0:
                    print("-Detected Downloaded Sample:")
                    for r in res["results"]["detected_downloaded_samples"]:
                        print("\t%s (on %s, %i/%i)" % (
                                r["sha256"],
                                r["date"],
                                r["positives"],
                                r["total"]
                            )
                        )

    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            if conf["VirusTotal"]["type"] != "public":
                vt = PrivateApi(conf["VirusTotal"]["key"])
                if args.subcommand == "hash":
                    response = vt.get_file_report(args.HASH)
                    if args.raw:
                        print(json.dumps(response, sort_keys=False, indent=4))
                        if args.extended:
                            response = vt.get_network_traffic(args.HASH)
                            print(json.dumps(response, sort_keys=False, indent=4))
                            response = vt.get_file_behaviour(args.HASH)
                            print(json.dumps(response, sort_keys=False, indent=4))
                    else:
                        if response["response_code"] != 200:
                            print("Error with the request (reponse code %i)" % response["response_code"])
                            sys.exit(1)
                        if response["results"]["response_code"] == 0:
                            print("File not found")
                            sys.exit(0)
                        print("[+] Detection: %i / %i" % (
                                response["results"]["positives"],
                                response["results"]["total"]
                            )
                        )
                        print("[+] MD5: %s" % response["results"]["md5"])
                        print("[+] SHA1: %s" % response["results"]["sha1"])
                        print("[+] SHA256: %s" % response["results"]["sha256"])
                        print("[+] First Seen: %s" % response["results"]["first_seen"])
                        print("[+] Last Seen: %s" % response["results"]["last_seen"])
                        print("[+] Link: %s" % response["results"]["permalink"])
                elif args.subcommand == "hashlist":
                    with open(args.FILE, 'r') as infile:
                        data = infile.read().split()
                    hash_list = list(set([a.strip() for a in data]))
                    print("Hash;Found;Detection;Total AV;First Seen;Last Seen;Link")
                    for h in hash_list:
                        response = vt.get_file_report(h)
                        if response["response_code"] != 200:
                            print("Error with the request (reponse code %i)" % response["response_code"])
                            print(json.dumps(response, sort_keys=False, indent=4))
                            print("Quitting...")
                            sys.exit(1)
                        if "response_code" in response["results"]:
                            if response["results"]["response_code"] == 0:
                                print("%s;Not found;;;;;" % h)
                            else:
                                print("%s;Found;%i;%i;%s;%s;%s" % (
                                        h,
                                        response["results"]["positives"],
                                        response["results"]["total"],
                                        response["results"]["first_seen"],
                                        response["results"]["last_seen"],
                                        response["results"]["permalink"]
                                    )
                                )
                        else:
                            print("%s;Not found;;;;;" % h)
                elif args.subcommand == "domainlist":
                    with open(args.FILE, 'r') as infile:
                        data = infile.read().split()
                    for d in data:
                        print("################ Domain %s" % d.strip())
                        res = vt.get_domain_report(d.strip())
                        self.print_domaininfo(res)
                elif args.subcommand == "domain":
                    res = vt.get_domain_report(args.DOMAIN)
                    if args.json:
                        print(json.dumps(res, sort_keys=False, indent=4))
                    else:
                        self.print_domaininfo(res)
                elif args.subcommand == "ip":
                    res = vt.get_ip_report(args.IP)
                    print(json.dumps(res, sort_keys=False, indent=4))
                elif args.subcommand == "url":
                    res = vt.get_url_report(args.URL)
                    print(json.dumps(res, sort_keys=False, indent=4))
                else:
                    self.parser.print_help()
            else:
                vt = PublicApi(conf["VirusTotal"]["key"])
                if args.subcommand == "hash":
                    response = vt.get_file_report(args.HASH)
                    if args.raw:
                        print(json.dumps(response, sort_keys=False, indent=4))
                    else:
                        if response["response_code"] != 200:
                            print("Error with the request (reponse code %i)" % response["response_code"])
                            sys.exit(1)
                        if response["results"]["response_code"] == 0:
                            print("File not found")
                            sys.exit(0)
                        print("[+] Detection: %i / %i" % (
                                response["results"]["positives"],
                                response["results"]["total"]
                            )
                        )
                        print("[+] MD5: %s" % response["results"]["md5"])
                        print("[+] SHA1: %s" % response["results"]["sha1"])
                        print("[+] SHA256: %s" % response["results"]["sha256"])
                        print("[+] Scan Date: %s" % response["results"]["scan_date"])
                        print("[+] Link: %s" % response["results"]["permalink"])
                elif args.subcommand == "hashlist":
                    with open(args.FILE, 'r') as infile:
                        data = infile.read().split()
                    hash_list = list(set([a.strip() for a in data]))
                    print("Hash;Found;Detection;Total AV;Link")
                    for h in hash_list:
                        response = vt.get_file_report(h)
                        if response["response_code"] != 200:
                            print("Error with the request (reponse code %i)" % response["response_code"])
                            print(json.dumps(response, sort_keys=False, indent=4))
                            print("Quitting...")
                            sys.exit(1)
                        if "response_code" in response["results"]:
                            if response["results"]["response_code"] == 0:
                                print("%s;Not found;;;" % h)
                            else:
                                print("%s;Found;%i;%i;%s" % (
                                        h,
                                        response["results"]["positives"],
                                        response["results"]["total"],
                                        response["results"]["permalink"]
                                    )
                                )
                        else:
                            print("%s;Not found;;;" % h)
                elif args.subcommand == "domain":
                    res = vt.get_domain_report(args.DOMAIN)
                    if args.json:
                        print(json.dumps(res, sort_keys=False, indent=4))
                    else:
                        self.print_domaininfo(res)
                elif args.subcommand == "ip":
                    res = vt.get_ip_report(args.IP)
                    print(json.dumps(res, sort_keys=False, indent=4))
                elif args.subcommand == "url":
                    res = vt.get_url_report(args.URL)
                    print(json.dumps(res, sort_keys=False, indent=4))
                elif args.subcommand == "domainlist":
                    print("Not implemented yet with public access")
                else:
                    self.parser.print_help()
        else:
            self.parser.print_help()
