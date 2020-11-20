#! /usr/bin/env python
import sys
import json
import hashlib
import pytz
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.utils import json_serial, typeguess, unbracket
from pythreatgrid2 import ThreatGrid, ThreatGridError


class CommandThreatGrid(Command):
    """
    # Threat Grid

    **Search in Threat Grid database through the API**

    * Search for a domain: `harpoon threatgrid search domain DOMAIN`
    * Search for a hash : ``harpoon threatgrid hash HASH`

    """
    name = "threatgrid"
    description = "Request Threat Grid API"
    config = {'ThreatGrid': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('hash', help='Request info on a hash')
        parser_a.add_argument('HASH', help='Hash')
        parser_a.add_argument('--json', '-j', action='store_true', help='Show raw json')
        parser_a.set_defaults(subcommand='hash')
        parser_b = subparsers.add_parser('search', help='Search in Total Hash database')
        parser_b.add_argument('--json', '-j', action='store_true', help='Show raw json')
        parser_b.add_argument('TYPE', help='type of the query (can be checksum, checksum_sample, path, path_sample, path_artifact, path_deleted, url, registry_key, domain, domain_dns_lookup, domain_http_request, ip, ip_dns_lookup, ip_src, ip_dst, ioc, tag)')
        parser_b.add_argument('QUERY', help='query')
        parser_b.set_defaults(subcommand='search')
        parser_c = subparsers.add_parser('networklist', help='Read list of network indicators (domain or IP) from a file a search for related samples')
        parser_c.add_argument('FILE', help='File')
        parser_c.set_defaults(subcommand='networklist')
        self.parser = parser

    def run(self, conf, args, plugins):
        tg = ThreatGrid(conf['ThreatGrid']['key'])
        if 'subcommand' in args:
            if args.subcommand == "search":
                try:
                    res = tg.search_samples(unbracket(args.QUERY), type=args.TYPE)
                except ThreatGridError:
                    print("Invalid type")
                if args.json:
                    print(json.dumps(res, sort_keys=True, indent=4))
                else:
                    if len(res['items']) == 0:
                        print('Not found')
                    else:
                        already = []
                        for item in res['items']:
                            if item['sample_sha256'] not in already:
                                print("%s - %s - %s" % (item['ts'], item['sample_sha256'], "https://panacea.threatgrid.com/mask/samples/" + item['sample']))
                                already.append(item['sample_sha256'])
            elif args.subcommand == 'hash':
                hash_type = {32: 'md5', 40: 'sha1', 64: 'sha256'}
                res = tg.get_sample(args.HASH, type=hash_type[len(args.HASH)])
                if len(res['items']) > 0:
                    item = res['items'][0]
                    print("Sample submitted the %s: https://panacea.threatgrid.com/mask/samples/%s" % (item['submitted_at'], item['id']))
                    idd = item['id']
                    res = tg.get_sample_threats(idd)
                    if args.json:
                        print(json.dumps(res, sort_keys=True, indent=4))
                    else:
                        print('\nThreats:')
                        for t in res['bis']:
                            print("-%s" % t)
                else:
                    print('Hash not found')
            elif args.subcommand == 'networklist':
                with open(args.FILE, 'r') as f:
                    data = f.read().split('\n')
                for d in data:
                    target = unbracket(d.strip())
                    gtype = typeguess(target)
                    print(target)
                    res = tg.search_samples(target, type=gtype)
                    if len(res['items']) > 0:
                        already = []
                        for item in res['items']:
                            if item['sample_sha256'] not in already:
                                print("-%s: https://panacea.threatgrid.com/mask/samples/%s %s" % (item['ts'][:10], item['sample'], item['sample_sha256']))
                                already.append(item['sample_sha256'])

                    else:
                        print('-Nothing found')
                    print('')
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        if type == "domain":
            print("[+] Checking ThreatGrid...")
            try:
                tg = ThreatGrid(conf["ThreatGrid"]["key"])
                res = tg.search_samples(query, type="domain")
                already = []
                if "items" in res:
                    for r in res["items"]:
                        if r["sample_sha256"] not in already:
                            d = parse(r["ts"]).astimezone(pytz.utc)
                            data["malware"].append(
                                {
                                    "hash": r["sample_sha256"],
                                    "date": d,
                                    "source": "ThreatGrid",
                                }
                            )
                            already.append(r["sample_sha256"])
            except ThreatGridError as e:
                print("Failed to connect to Threat Grid: %s" % e.message)
        elif type == "ip":
            print("[+] Checking ThreatGrid...")
            try:
                tg = ThreatGrid(conf["ThreatGrid"]["key"])
                res = tg.search_samples(query, type="ip")
                already = []
                if "items" in res:
                    for r in res["items"]:
                        if r["sample_sha256"] not in already:
                            d = parse(r["ts"]).astimezone(pytz.utc)
                            data["malware"].append(
                                {
                                    "hash": r["sample_sha256"],
                                    "date": d,
                                    "source": "ThreatGrid",
                                }
                            )
                            already.append(r["sample_sha256"])
            except ThreatGridError as e:
                print("Failed to connect to Threat Grid: %s" % e.message)
        elif type =="hash":
            print("[+] Checking ThreatGrid...")
            try:
                tg = ThreatGrid(conf["ThreatGrid"]["key"])
                hash_type = {32: 'md5', 40: 'sha1', 64: 'sha256'}
                res = tg.get_sample(query, type=hash_type[len(query)])
                for item in res["items"]:
                    data["samples"].append({
                        "source": "ThreatGrid",
                        "date": parse(item["submitted_at"]).astimezone(pytz.utc),
                        "url": "https://panacea.threatgrid.com/mask/samples/{}".format(item['id'])
                    })
            except ThreatGridError as e:
                print("Failed to connect to Threat Grid: %s" % e.message)
