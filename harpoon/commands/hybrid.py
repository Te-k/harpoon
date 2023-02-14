#! /usr/bin/env python
import json
import os

import pytz
from dateutil.parser import parse

from harpoon.commands.base import Command
from harpoon.lib.hybrid import HybridAnalysis, HybridAnalysisFailed
from harpoon.lib.utils import json_serial


class CommandHybridAnalysis(Command):
    """
    # HybridAnalysis

    **Query Hybrid Analysis Sandbox information (https://www.hybrid-analysis.com/)**

    Requests:
    * `harpoon hybrid hash 52c408a3dd38743a179ef800b390bbac` : Give information on a hash
    * `harpoon hybrid quota` : show quota information
    * `harpoon hybrid search host:95.181.53.78` : search in Hybrid Analysis samples
    * `harpoon analysis 52c408a3dd38743a179ef800b390bbac 100` : gived detailed sandbox report

    Search operators :
    * host:95.181.53.78
    * port:3448
    * domain:checkip.dyndns.org
    * vxfamily:upatre
    * indicatorid:network-6 (Show all reports matching 'Contacts Random Domain Names')
    * filetype:jar
    * filetype_tag:hwp
    * url:google
    * similar-to:59f629287c1ce2bcb39e4bc41633756e516bf04909750eba1cd2c787d02d3347
    * authentihash:hash
    * tag:teslacrypt
    """
    name = "hybrid"
    description = "Requests Hybrid Analysis platform"
    config = {'HybridAnalysis': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('hash', help='Request info on a hash')
        parser_a.add_argument('HASH', help='Hash')
        parser_a.set_defaults(subcommand='hash')
        parser_c = subparsers.add_parser('domain', help='Search samples communicating with a domain')
        parser_c.add_argument('DOMAIN', help='Domain')
        parser_c.set_defaults(subcommand='domain')
        parser_d = subparsers.add_parser('ip', help='Search samples communicating with a, IP address')
        parser_d.add_argument('IP', help='IP address')
        parser_d.set_defaults(subcommand='ip')
        parser_e = subparsers.add_parser('search', help='Search in HybridAnalysis')
        parser_e.add_argument('QUERY', help='query', nargs="+")
        parser_e.set_defaults(subcommand='search')
        parser_f = subparsers.add_parser('dl', help='Download a sample')
        parser_f.add_argument('HASH', help='SHA256 of the file')
        parser_f.set_defaults(subcommand='dl')
        self.parser = parser

    def run(self, args, plugins):
        ha = HybridAnalysis(self._config_data['HybridAnalysis']['key'])
        if 'subcommand' in args:
            if args.subcommand == "search":
                try:
                    data = {}
                    for d in args.QUERY:
                        if ":" in d:
                            dd = d.split(":")
                            data[dd[0]] = dd[1]
                    res = ha.search_terms(data)
                except HybridAnalysisFailed as e:
                    print("Query failed")
                    print(e)
                else:
                    print(json.dumps(res, indent=4, separators=(',', ': '), default=json_serial))
            elif args.subcommand == 'hash':
                try:
                    res = ha.search_hash(args.HASH)
                except HybridAnalysisFailed as e:
                    print("Query failed")
                    print(e)
                else:
                    print(json.dumps(res, indent=4, separators=(',', ': '), default=json_serial))
            elif args.subcommand == 'domain':
                try:
                    res = ha.search_terms({"domain": args.DOMAIN})
                except HybridAnalysisFailed as e:
                    print("Query failed")
                    print(e)
                else:
                    print(json.dumps(res, indent=4, separators=(',', ': '), default=json_serial))
            elif args.subcommand == 'ip':
                try:
                    res = ha.search_terms({"host": args.IP})
                except HybridAnalysisFailed as e:
                    print("Query failed")
                    print(e)
                else:
                    print(json.dumps(res, indent=4, separators=(',', ': '), default=json_serial))
            elif args.subcommand == 'dl':
                if os.path.isfile(args.HASH):
                    os.remove(args.HASH)
                try:
                    res = ha.overview_sample(args.HASH)
                except HybridAnalysisFailed as e:
                    print("Query failed")
                    print(e)
                else:
                    with open(args.HASH, "wb+") as f:
                        f.write(res)
                    print("Sample saved as {}".format(args.HASH))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data):
        ha = HybridAnalysis(self._config_data['HybridAnalysis']['key'])
        if type == "domain":
            print("[+] Checking HybridAnalysis...")
            try:
                res = ha.search_terms({"domain": query})
            except HybridAnalysisFailed:
                print("Query failed")
            else:
                for r in res["result"]:
                    data["malware"].append({
                        "source": "HybridAnalysis",
                        "hash": r["sha256"],
                        "date": parse(r["analysis_start_time"]).astimezone(pytz.utc)
                    })
        elif type == "ip":
            print("[+] Checking HybridAnalysis...")
            try:
                res = ha.search_terms({"host": query})
            except HybridAnalysisFailed:
                print("Query failed")
            else:
                for r in res["result"]:
                    data["malware"].append({
                        "source": "HybridAnalysis",
                        "hash": r["sha256"],
                        "date": parse(r["analysis_start_time"]).astimezone(pytz.utc)
                    })
        elif type == "hash":
            print("[+] Checking HybridAnalysis...")
            try:
                res = ha.search_hash(query)
            except HybridAnalysisFailed:
                pass
            else:
                for sample in res:
                    data["samples"].append({
                        "source": "HybridAnalysis",
                        "date": parse(sample["analysis_start_time"]).astimezone(pytz.utc),
                        "url": "https://www.hybrid-analysis.com/sample/{}".format(sample["sha256"]),
                        "infos": {
                            "Verdict": sample["verdict"],
                            "SubmitName": sample["submit_name"],
                            "Malware Family": sample["vx_family"]
                            }
                    })
                    if "domains" in sample:
                        for d in sample["domains"]:
                            data["network"].append({
                                "source": "HybridAnalysis",
                                "url": "https://www.hybrid-analysis.com/sample/{}".format(sample["sha256"]),
                                "host": d
                            })
                    if "hosts" in sample:
                        for d in sample["hosts"]:
                            data["network"].append({
                                "source": "HybridAnalysis",
                                "url": "https://www.hybrid-analysis.com/sample/{}".format(sample["sha256"]),
                                "host": d
                            })
