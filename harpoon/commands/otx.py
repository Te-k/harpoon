#! /usr/bin/env python
import sys
import json
import pytz
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.utils import typeguess
from OTXv2 import OTXv2, IndicatorTypes

OTX_TYPES = {
    "domain": IndicatorTypes.DOMAIN,
    "IPv4": IndicatorTypes.IPv4,
    "IPv6": IndicatorTypes.IPv6,
    "url": IndicatorTypes.URL,
    "md5": IndicatorTypes.FILE_HASH_MD5,
    "sha1": IndicatorTypes.FILE_HASH_SHA1,
    "sha256": IndicatorTypes.FILE_HASH_SHA256,
    "pehash": IndicatorTypes.FILE_HASH_PEHASH,
    "imphash": IndicatorTypes.FILE_HASH_IMPHASH,
    "cidr": IndicatorTypes.CIDR,
    "file_path": IndicatorTypes.FILE_PATH,
    "hostname": IndicatorTypes.HOSTNAME,
    "mutex": IndicatorTypes.MUTEX,
    "cve": IndicatorTypes.CVE
}


class CommandOtx(Command):
    """
    # AlienVault Open Threat Exchange

    **Requests information from AlienVault Open Threat Exchange https://www.alienvault.com/open-threat-exchange**

    * Search for an indicator: `harpoon otx -s 127.0.0.1`
    * Search for a list of indicators from a file: `harpoon otx -f FILE`
    * Get information on a pulse: `harpoon otx -p PULSE_ID`

    You can get raw JSON output with `-j`, and gives the IOC type with `-t`
    """
    name = "otx"
    description = "Requests information from AlienVault OTX"
    config = { 'AlienVaultOtx': ['key']}

    def add_arguments(self, parser):
        parser.add_argument('--pulse', '-p',  help='Event infos')
        parser.add_argument('--search', '-s',  help='Search for indicators')
        parser.add_argument('--file', '-f',  help='Check from a list of indicators in a file')
        parser.add_argument('--raw', '-r', help='Print raw information', action='store_true')
        parser.add_argument('--json', '-j', help='Print json information', action='store_true')
        parser.add_argument('--type', '-t', help='Type for search', default="guess", choices=["guess", "domain", "IPv4", "IPv6", "url", "md5", "sha1", "sha256", "pehash", "imphash", "cidr", "file_path", "hostname", "mutex", "cve"])
        self.parser = parser

    def run(self, conf, args, plugins):
        otx = OTXv2(conf["AlienVaultOtx"]["key"])
        if args.pulse:
            try:
                indicators = otx.get_pulse_indicators(args.pulse)
            except Exception:
                print("Pulse not found")
            else:
                if args.json:
                    print(json.dumps(indicators, sort_keys=True, indent=4))
                elif args.raw:
                    for i in indicators:
                        print(i["indicator"])
                else:
                    for i in indicators:
                        if len(i["type"]) < 5:
                            t = "\t\t\t"
                        else:
                            t = "\t\t"

                        print("[+] %s %s%s%s" % (
                                i["created"],
                                i["type"],
                                t,
                                i["indicator"]
                            )
                        )
        elif args.search:
            if args.type == "guess":
                t = typeguess(args.search)
            else:
                t = args.type

            res = otx.get_indicator_details_full(
                OTX_TYPES[t],
                args.search
            )
            if args.json:
                print(json.dumps(res, sort_keys=True, indent=4))
            else:
                if 'analysis' in res:
                    if res['analysis']['analysis']:
                        analysis = res["analysis"]["analysis"]
                        print("File analysed the %s" % analysis["datetime_int"])
                        if "info" in analysis:
                            print("Infos:")
                            for r in analysis["info"]["results"]:
                                print("\t%s : %s" % (r, analysis["info"]["results"][r]))
                        if "exiftool" in analysis["plugins"]:
                            print("Exiftool:")
                            for r in analysis["plugins"]["exiftool"]["results"]:
                                print("\t%s : %s" % (r, analysis["plugins"]["exiftool"]["results"][r]))
                        if "yarad" in analysis["plugins"]:
                            print("Yara detection:")
                            for r in analysis["plugins"]["yarad"]["results"]['detection']:
                                print("\t%s : %s" % (r["category"], r["rule_name"]))

                        print("")
                    else:
                        print("No analysis on this file")
                else:
                    print("No analysis on this file")
                if len(res["general"]["pulse_info"]["pulses"]) > 0:
                    print("Listed in %s pulses" % len(res["general"]["pulse_info"]["pulses"]))
                    for p in res["general"]["pulse_info"]["pulses"]:
                        print("\t-%s" % p["name"])
                        print("\t\t%s" % p["description"].replace("\n", " "))
                        print("\t\tCreated: %s" % p["created"])
                        print("\t\tReferences: %s" % ", ".join(p["references"]))
                        print("\t\tid: %s" % p["id"])
                else:
                    print("Not listed in any pulse")
                if 'passive_dns' in res:
                    if len(res['passive_dns']['passive_dns']) > 0:
                        print("Passive DNS:")
                        for p in res['passive_dns']['passive_dns']:
                            print("\t%s%s on IP %s [%s -> %s]" % (
                                    p["hostname"],
                                    p["indicator_link"],
                                    p["address"],
                                    p["first"],
                                    p["last"]
                                )
                            )
                        print("")
                if 'url_list' in res:
                    if len(res['url_list']['url_list']) > 0:
                        print("URL list:")
                        for u in res['url_list']['url_list']:
                            if "result" in u:
                                if "urlworker" in u["result"]:
                                    if "ip" in u["result"]["urlworker"] :
                                        print("\t[%s] %s on IP %s" % (
                                                u["date"],
                                                u["url"],
                                                u["result"]["urlworker"]["ip"]
                                            )
                                        )
                                    else:
                                        print("\t[%s] %s" % (
                                                u["date"],
                                                u["url"]
                                            )
                                        )
                                else:
                                    print("\t[%s] %s" % (u["date"], u["url"]))
                            else:
                                print("\t[%s] %s" % (u["date"], u["url"]))
                        print("")
        elif args.file:
            with open(args.file, "r") as f:
                data = f.read().split("\n")
            for d in data:
                if d.strip() != "":
                    if args.type == "guess":
                        t = typeguess(d.strip())
                    else:
                        t = args.type

                    print("========== %s" % d.strip())
                    res = otx.get_indicator_details_full(
                        OTX_TYPES[t],
                        d.strip()
                    )
                    if len(res["general"]["pulse_info"]["pulses"]) > 0:
                        print("Listed in %s pulses" % len(res["general"]["pulse_info"]["pulses"]))
                        for p in res["general"]["pulse_info"]["pulses"]:
                            print("\t-%s" % p["name"])
                            print("\t\t%s" % p["description"].replace("\n", " "))
                            print("\t\tCreated: %s" % p["created"])
                            print("\t\tReferences: %s" % ", ".join(p["references"]))
                            print("\t\tid: %s" % p["id"])
                    else:
                        print("Not listed in any pulse")
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        if type == "domain":
            print("[+] Checking OTX...")
            try:
                otx = OTXv2(conf["AlienVaultOtx"]["key"])
                res = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, query)
                for pulse in res["general"]["pulse_info"]["pulses"]:
                    data["reports"].append({
                        "date": parse(pulse["created"]).astimezone(pytz.utc),
                        "title": pulse["name"],
                        "source": "OTX",
                        "url": "https://otx.alienvault.com/pulse/{}".format(pulse["id"])
                    })
                # Get Passive DNS
                if "passive_dns" in res:
                    for r in res["passive_dns"]["passive_dns"]:
                        data["passive_dns"].append({
                            "ip": r["hostname"],
                            "first": parse(r["first"]).astimezone(pytz.utc),
                            "last": parse(r["last"]).astimezone(pytz.utc),
                            "source": "OTX",
                        })
                if "url_list" in res:
                    for r in res["url_list"]["url_list"]:
                        if "result" in r:
                            data["urls"].append({
                                "date": parse(r["date"]).astimezone(pytz.utc),
                                "url": r["url"],
                                "ip": r["result"]["urlworker"]["ip"]
                                if "ip" in r["result"]["urlworker"]
                                else "",
                                "source": "OTX",
                            })
                        else:
                            data["urls"].append({
                                "date": parse(r["date"]).astimezone(pytz.utc),
                                "url": r["url"],
                                "ip": "",
                                "source": "OTX",
                            })
                # Some pulses have domains as hostnames
                res = otx.get_indicator_details_full(IndicatorTypes.HOSTNAME, query)
                for pulse in res["general"]["pulse_info"]["pulses"]:
                    data["reports"].append({
                        "date": parse(pulse["created"]).astimezone(pytz.utc),
                        "title": pulse["name"],
                        "source": "OTX",
                        "url": "https://otx.alienvault.com/pulse/{}".format(pulse["id"])
                    })
            except AttributeError:
                print("OTX crashed  ¯\_(ツ)_/¯")
        elif type == "ip":
            print("[+] Checking OTX...")
            try:
                otx = OTXv2(conf["AlienVaultOtx"]["key"])
                res = otx.get_indicator_details_full(IndicatorTypes.IPv4, query)
                for pulse in res["general"]["pulse_info"]["pulses"]:
                    data["reports"].append({
                        "date": parse(pulse["created"]).astimezone(pytz.utc),
                        "title": pulse["name"],
                        "source": "OTX",
                        "url": "https://otx.alienvault.com/pulse/{}".format(pulse["id"])
                    })
                # Get Passive DNS
                if "passive_dns" in res:
                    for r in res["passive_dns"]["passive_dns"]:
                        data["passive_dns"].append({
                            "domain": r["hostname"],
                            "first": parse(r["first"]).astimezone(pytz.utc),
                            "last": parse(r["last"]).astimezone(pytz.utc),
                            "source": "OTX",
                        })
                if "url_list" in res:
                    for r in res["url_list"]["url_list"]:
                        if "result" in r:
                            data["urls"].append({
                                "date": parse(r["date"]).astimezone(pytz.utc),
                                "url": r["url"],
                                "ip": r["result"]["urlworker"]["ip"]
                                if "ip" in r["result"]["urlworker"]
                                else "",
                                "source": "OTX",
                            })
                        else:
                            data["urls"].append({
                                "date": parse(r["date"]).astimezone(pytz.utc),
                                "url": r["url"],
                                "ip": "",
                                "source": "OTX",
                            })
            except AttributeError:
                print("OTX crashed  ¯\_(ツ)_/¯")
        elif type == "hash":
            t = typeguess(query)
            print("[+] Checking OTX...")
            try:
                otx = OTXv2(conf["AlienVaultOtx"]["key"])
                res = otx.get_indicator_details_full(OTX_TYPES[t], query)
                for pulse in res["general"]["pulse_info"]["pulses"]:
                    data["reports"].append({
                        "date": parse(pulse["created"]).astimezone(pytz.utc),
                        "title": pulse["name"],
                        "source": "OTX",
                        "url": "https://otx.alienvault.com/pulse/{}".format(pulse["id"])
                    })
                if "analysis" in res:
                    if "analysis" in res["analysis"]:
                        if "plugins" in res["analysis"]["analysis"]:
                            if "cuckoo" in res["analysis"]["analysis"]["plugins"]:
                                done = []
                                for d in res["analysis"]["analysis"]["plugins"]["cuckoo"]["result"]["network"]["domains"]:
                                    data["network"].append({
                                        "source": "OTX",
                                        "url": "https://otx.alienvault.com/indicator/file/{}".format(query),
                                        "host": d["domain"],
                                        "host2": d["ip"]
                                    })
                                    done.append(d["ip"])
                                    done.append(d["domain"])
                                for ip in res["analysis"]["analysis"]["plugins"]["cuckoo"]["result"]["network"]["hosts"]:
                                    if ip["ip"] not in done:
                                        data["network"].append({
                                            "source": "OTX",
                                            "url": "https://otx.alienvault.com/indicator/file/{}".format(query),
                                            "host": ip["ip"],
                                        })

            except AttributeError:
                print("OTX crashed  ¯\_(ツ)_/¯")
