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
        parser_b = subparsers.add_parser('list', help='Request a list of hashes')
        parser_b.add_argument('FILE',  help='File containing the domains')
        parser_b.set_defaults(subcommand='file')
        self.parser = parser

    def run(self, conf, args):
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
                elif args.subcommand == "list":
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
                else:
                    self.parser.print_help()
            else:
                vt = PublicApi(conf["VirusTotal"]["key"])
                if args.subdommand == "hash":
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
                elif args.subcommand == "list":
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
                else:
                    self.parser.print_help()
        else:
            self.parser.print_help()
