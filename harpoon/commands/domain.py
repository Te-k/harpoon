#! /usr/bin/env python
import sys
import requests
import os
import json
import datetime
import urllib.request
import tarfile
import geoip2.database
import re
import subprocess
import glob
import shutil
import pyasn
import pypdns
import pytz
from IPy import IP
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket
from harpoon.lib.robtex import Robtex, RobtexError
from harpoon.lib.urlscan import UrlScan
from OTXv2 import OTXv2, IndicatorTypes
from virus_total_apis import PublicApi, PrivateApi
from pygreynoisev1 import GreyNoise, GreyNoiseError
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.enrichment import EnrichmentRequest
from pythreatgrid2 import ThreatGrid, ThreatGridError
from pybinaryedge import BinaryEdge, BinaryEdgeException, BinaryEdgeNotFound


class CommandDomain(Command):
    """
    # Domain

    """
    name = "domain"
    description = "Gather information on a domain"
    config = None
    geocity = os.path.join(os.path.expanduser('~'), '.config/harpoon/GeoLite2-City.mmdb')
    geoasn = os.path.join(os.path.expanduser('~'), '.config/harpoon/GeoLite2-ASN.mmdb')
    asnname = os.path.join(os.path.expanduser('~'), '.config/harpoon/asnnames.csv')
    asncidr = os.path.join(os.path.expanduser('~'), '.config/harpoon/asncidr.dat')

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('info', help='Information on an domain')
        parser_a.add_argument('DOMAIN', help='Domain')
        parser_a.set_defaults(subcommand='info')
        parser_b = subparsers.add_parser('intel', help='Gather Threat Intelligence information on a domain')
        parser_b.add_argument('DOMAIN', help='Domain')
        parser_b.set_defaults(subcommand='intel')
        self.parser = parser

    def ipinfo(self, ip):
        """
        Return information on an IP address
        {"asn", "asn_name", "city", "country"}
        """
        ipinfo = {}
        try:
            citydb = geoip2.database.Reader(self.geocity)
            res = citydb.city(ip)
            ipinfo["city"] = res.city.name
            ipinfo["country"] = res.country.name
        except geoip2.errors.AddressNotFoundError:
            ipinfo["city"] = "Unknown"
            ipinfo["country"] = "Unknown"
        try:
            asndb = geoip2.database.Reader(self.geoasn)
            res = asndb.asn(ip)
            ipinfo["asn"] = res.autonomous_system_number
            ipinfo["asn_name"] = res.autonomous_system_organization
        except geoip2.errors.AddressNotFoundError:
            ipinfo["asn"] = ""
            ipinfo["asn_name"] = ""
            # FIXME: check in text files if not found
            # TODO: add private
        return ipinfo

    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            if args.subcommand == 'info':
                print("Not implemented yet")
            elif args.subcommand == "intel":
                # Start with MISP and OTX to get Intelligence Reports
                print('###################### %s ###################' % args.DOMAIN)
                passive_dns = []
                urls = []
                malware = []
                files = []
                # OTX
                otx_e = plugins['otx'].test_config(conf)
                if otx_e:
                    print('[+] Downloading OTX information....')
                    try:
                        otx = OTXv2(conf["AlienVaultOtx"]["key"])
                        res = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, unbracket(args.DOMAIN))
                        otx_pulses =  res["general"]["pulse_info"]["pulses"]
                        # Get Passive DNS
                        if "passive_dns" in res:
                            for r in res["passive_dns"]["passive_dns"]:
                                passive_dns.append({
                                    "ip": r['hostname'],
                                    "first": parse(r["first"]).astimezone(pytz.utc),
                                    "last": parse(r["last"]).astimezone(pytz.utc),
                                    "source" : "OTX"
                                })
                        if "url_list" in res:
                            for r in res["url_list"]["url_list"]:
                                if "result" in r:
                                    urls.append({
                                        "date": parse(r["date"]).astimezone(pytz.utc),
                                        "url": r["url"],
                                        "ip": r["result"]["urlworker"]["ip"] if "ip" in r["result"]["urlworker"] else "" ,
                                        "source": "OTX"
                                    })
                                else:
                                    urls.append({
                                        "date": parse(r["date"]).astimezone(pytz.utc),
                                        "url": r["url"],
                                        "ip": "",
                                        "source": "OTX"
                                    })
                    except AttributeError:
                        print('OTX crashed  ¯\_(ツ)_/¯')
                # UrlScan
                us = UrlScan()
                print('[+] Downloading UrlScan information....')
                res = us.search(args.DOMAIN)
                for r in res['results']:
                    urls.append({
                        "date": parse(r["task"]["time"]).astimezone(pytz.utc),
                        "url": r["page"]["url"],
                        "ip": r["page"]["ip"] if "ip" in r["page"] else "",
                        "source": "UrlScan"
                    })

                # CIRCL
                circl_e = plugins['circl'].test_config(conf)
                if circl_e:
                    print('[+] Downloading CIRCL passive DNS information....')
                    x = pypdns.PyPDNS(
                        basic_auth=(
                            conf['Circl']['user'],
                            conf['Circl']['pass']
                        )
                    )
                    res = x.query(unbracket(args.DOMAIN))
                    for answer in res:
                        passive_dns.append({
                            "ip": answer['rdata'],
                            "first": answer['time_first'].astimezone(pytz.utc),
                            "last": answer['time_last'].astimezone(pytz.utc),
                            "source" : "CIRCL"
                        })
                # BinaryEdge
                be_e = plugins['binaryedge'].test_config(conf)
                if be_e:
                    print('[+] Downloading BinaryEdge information....')
                    try:
                        be = BinaryEdge(conf['BinaryEdge']['key'])
                        res = be.domain_dns(unbracket(args.DOMAIN))
                        for d in res['events']:
                            if "A" in d:
                                for a in d['A']:
                                    passive_dns.append({
                                        "ip": a,
                                        "first": parse(d['updated_at']).astimezone(pytz.utc),
                                        "last": parse(d['updated_at']).astimezone(pytz.utc),
                                        "source" : "BinaryEdge"
                                    })
                    except BinaryEdgeException:
                        print('You need a paid BinaryEdge subscription for this request')
                # RobTex
                print('[+] Downloading Robtex information....')
                rob = Robtex()
                res = rob.get_pdns_domain(args.DOMAIN)
                for d in res:
                    if d['rrtype'] in ['A', 'AAAA']:
                        passive_dns.append({
                            'first': d['time_first_o'].astimezone(pytz.utc),
                            'last': d['time_last_o'].astimezone(pytz.utc),
                            'ip': d['rrdata'],
                            'source': 'Robtex'
                        })

                # PT
                pt_e = plugins['pt'].test_config(conf)
                if pt_e:
                    try:
                        pt_osint = {}
                        ptout = False
                        print('[+] Downloading Passive Total information....')
                        client = DnsRequest(conf['PassiveTotal']['username'], conf['PassiveTotal']['key'])
                        raw_results = client.get_passive_dns(query=unbracket(args.DOMAIN))
                        if "results" in raw_results:
                            for res in raw_results["results"]:
                                passive_dns.append({
                                    "first": parse(res["firstSeen"]).astimezone(pytz.utc),
                                    "last": parse(res["lastSeen"]).astimezone(pytz.utc),
                                    "ip": res["resolve"],
                                    "source": "PT"
                                })
                        if "message" in raw_results:
                            if "quota_exceeded" in raw_results["message"]:
                                print("PT quota exceeded")
                                ptout = True
                        if not ptout:
                            client2 = EnrichmentRequest(conf["PassiveTotal"]["username"], conf["PassiveTotal"]['key'])
                            # Get OSINT
                            # TODO: add PT projects here
                            pt_osint = client2.get_osint(query=unbracket(args.DOMAIN))
                            # Get malware
                            raw_results = client2.get_malware(query=unbracket(args.DOMAIN))
                            if "results" in raw_results:
                                for r in raw_results["results"]:
                                    malware.append({
                                        'hash': r["sample"],
                                        'date': parse(r['collectionDate']).astimezone(pytz.utc),
                                        'source' : 'PT (%s)' % r["source"]
                                    })
                    except requests.exceptions.ReadTimeout:
                        print("PT: Time Out")
                # VT
                vt_e = plugins['vt'].test_config(conf)
                if vt_e:
                    if conf["VirusTotal"]["type"] != "public":
                        print('[+] Downloading VT information....')
                        vt = PrivateApi(conf["VirusTotal"]["key"])
                        res = vt.get_domain_report(unbracket(args.DOMAIN))
                        if "results" in res:
                            if "resolutions" in res['results']:
                                for r in res["results"]["resolutions"]:
                                    passive_dns.append({
                                        "first": parse(r["last_resolved"]).astimezone(pytz.utc),
                                        "last": parse(r["last_resolved"]).astimezone(pytz.utc),
                                        "ip": r["ip_address"],
                                        "source": "VT"
                                    })
                            if "undetected_downloaded_samples" in res['results']:
                                for r in res['results']['undetected_downloaded_samples']:
                                    files.append({
                                        'hash': r['sha256'],
                                        'date': parse(r['date']).astimezone(pytz.utc) if 'date' in r else '',
                                        'source' : 'VT'
                                    })
                            if "undetected_referrer_samples" in res['results']:
                                for r in res['results']['undetected_referrer_samples']:
                                    files.append({
                                        'hash': r['sha256'],
                                        'date': parse(r['date']).astimezone(pytz.utc) if 'date' in r else '',
                                        'source' : 'VT'
                                    })
                            if "detected_downloaded_samples" in res['results']:
                                for r in res['results']['detected_downloaded_samples']:
                                    malware.append({
                                        'hash': r['sha256'],
                                        'date': parse(r['date']).astimezone(pytz.utc),
                                        'source' : 'VT'
                                    })
                            if "detected_referrer_samples" in res['results']:
                                for r in res['results']['detected_referrer_samples']:
                                    if "date" in r:
                                        malware.append({
                                            'hash': r['sha256'],
                                            'date': parse(r['date']).astimezone(pytz.utc),
                                            'source' : 'VT'
                                        })
                            if "detected_urls" in res['results']:
                                for r in res['results']['detected_urls']:
                                    urls.append({
                                        'date': parse(r['scan_date']).astimezone(pytz.utc),
                                        'url': r['url'],
                                        'ip': '',
                                        'source': 'VT'
                                    })
                    else:
                        vt_e = False
                tg_e = plugins['threatgrid'].test_config(conf)
                if tg_e:
                    try:
                        print('[+] Downloading Threat Grid....')
                        tg = ThreatGrid(conf['ThreatGrid']['key'])
                        res = tg.search_samples(unbracket(args.DOMAIN), type='domain')
                        already = []
                        if 'items' in res:
                            for r in res['items']:
                                if r['sample_sha256'] not in already:
                                    d = parse(r['ts']).astimezone(pytz.utc)
                                    malware.append({
                                        'hash': r["sample_sha256"],
                                        'date': d,
                                        'source' : 'ThreatGrid'
                                    })
                                    already.append(r['sample_sha256'])
                    except ThreatGridError as e:
                        print("Failed to connect to Threat Grid: %s" % e.message)

                # TODO: Add MISP
                print('----------------- Intelligence Report')
                if otx_e:
                    if len(otx_pulses):
                        print('OTX:')
                        for p in otx_pulses:
                            print(' -%s (%s - %s)' % (
                                    p['name'],
                                    p['created'][:10],
                                    "https://otx.alienvault.com/pulse/" + p['id']
                                )
                            )
                    else:
                        print('OTX: Not found in any pulse')
                if pt_e:
                    if "results" in pt_osint:
                        if len(pt_osint["results"]):
                            if len(pt_osint["results"]) == 1:
                                if "name" in pt_osint["results"][0]:
                                    print("PT: %s %s" % (pt_osint["results"][0]["name"], pt_osint["results"][0]["sourceUrl"]))
                                else:
                                    print("PT: %s" % (pt_osint["results"][0]["sourceUrl"]))
                            else:
                                print("PT:")
                                for r in pt_osint["results"]:
                                    if "name" in r:
                                        print("-%s %s" % (r["name"], r["sourceUrl"]))
                                    else:
                                        print("-%s" % (r["sourceUrl"]))
                        else:
                            print("PT: Nothing found!")
                    else:
                        print("PT: Nothing found!")


                if len(malware) > 0:
                    print('----------------- Malware')
                    for r in sorted(malware, key=lambda x: x["date"]):
                        print("[%s] %s %s" % (
                                r["source"],
                                r["hash"],
                                r["date"].strftime("%Y-%m-%d")
                            )
                        )
                if len(files) > 0:
                    print('----------------- Files')
                    for r in files:
                        if r['date'] != '':
                            print("[%s] %s (%s)" % (
                                    r["source"],
                                    r["hash"],
                                    r["date"].strftime("%Y-%m-%d")
                                )
                            )
                        else:
                            print("[%s] %s" % (
                                    r["source"],
                                    r["hash"],
                                )
                            )
                if len(urls) > 0:
                    print('----------------- Urls')
                    for r in sorted(urls, key=lambda x: x["date"], reverse=True):
                        print("[%s] %s - %s %s" % (
                                r["source"],
                                r["url"],
                                r["ip"],
                                r["date"].strftime("%Y-%m-%d")
                            )
                        )
                # TODO: add ASN + location info here
                if len(passive_dns) > 0:
                    print('----------------- Passive DNS')
                    for r in sorted(passive_dns, key=lambda x: x["first"], reverse=True):
                        print("[+] %-40s (%s -> %s)(%s)" % (
                                r["ip"],
                                r["first"].strftime("%Y-%m-%d"),
                                r["last"].strftime("%Y-%m-%d"),
                                r["source"]
                            )
                        )

            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
