#! /usr/bin/env python
import sys
import json
import hashlib
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
    config = {'HybridAnalysis': ['key', 'secret']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('hash', help='Request info on a hash')
        parser_a.add_argument('HASH', help='Hash')
        parser_a.set_defaults(subcommand='hash')
        parser_b = subparsers.add_parser('analysis', help='Request details on an analysis')
        parser_b.add_argument('HASH', help='Hash')
        parser_b.set_defaults(subcommand='analysis')
        parser_c = subparsers.add_parser('help', help='Help on search terms')
        parser_c.set_defaults(subcommand='help')
        parser_f = subparsers.add_parser('quota', help='Print information on Hybrid Analysis Quota')
        parser_f.set_defaults(subcommand='quota')
        parser_e = subparsers.add_parser('search', help='Search in Total Hash database')
        parser_e.add_argument('QUERY', help='query')
        parser_e.set_defaults(subcommand='search')
        self.parser = parser

    def run(self, conf, args, plugins):
        ha = HybridAnalysis(conf['HybridAnalysis']['key'], conf['HybridAnalysis']['secret'])
        if 'subcommand' in args:
            if args.subcommand == 'quota':
                res = ha.quota()
                print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))
            elif args.subcommand == "search":
                try:
                    res = ha.search(args.QUERY)
                except HybridAnalysisFailed:
                    print("File not found")
                else:
                    print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))
            elif args.subcommand == 'hash':
                try:
                    res = ha.get_report(args.HASH)
                except HybridAnalysisFailed:
                    print("File not found")
                else:
                    print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))
            elif args.subcommand == 'analysis':
                try:
                    res = ha.get_last_analysis(args.HASH)
                except HybridAnalysisFailed:
                    print("File not found")
                else:
                    print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))
            elif args.subcommand == 'help':
                print("""
Example of search operators:
host:95.181.53.78
port:3448
domain:checkip.dyndns.org
vxfamily:upatre
indicatorid:network-6 (Show all reports matching 'Contacts Random Domain Names')
filetype:jar
filetype_tag:hwp
url:google
similar-to:59f629287c1ce2bcb39e4bc41633756e516bf04909750eba1cd2c787d02d3347
authentihash:hash
tag:teslacrypt
                """)
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        ha = HybridAnalysis(conf['HybridAnalysis']['key'], conf['HybridAnalysis']['secret'])
        if type == "domain":
            print("[+] Checking HybridAnalysis...")
            try:
                res = ha.search("domain:{}".format(query))
            except HybridAnalysisFailed:
                print("Query failed")
            else:
                for r in res["result"]:
                    data["malware"].append({
                        "source": "HybridAnalysis",
                        "hash": r["sha256"],
                        "date": parse(r["start_time"]).astimezone(pytz.utc)
                    })
        elif type == "ip":
            print("[+] Checking HybridAnalysis...")
            try:
                res = ha.search("host:{}".format(query))
            except HybridAnalysisFailed:
                print("Query failed")
            else:
                for r in res["result"]:
                    data["malware"].append({
                        "source": "HybridAnalysis",
                        "hash": r["sha256"],
                        "date": parse(r["start_time"]).astimezone(pytz.utc)
                    })
        elif type == "hash":
            print("[+] Checking HybridAnalysis...")
            try:
                res = ha.get_report(query)
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
                            "Submitname": sample["submitname"],
                            "Malware Family": sample["vxfamily"]
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
