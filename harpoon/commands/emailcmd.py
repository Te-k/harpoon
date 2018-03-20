#! /usr/bin/env python
import sys
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
from IPy import IP
from dateutil.parser import parse
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket
from OTXv2 import OTXv2, IndicatorTypes
from passivetotal.libs.whois import WhoisRequest
from github import Github, UnknownObjectException
from harpoon.lib.pgp import Pgp


class CommandEmail(Command):
    """
    # Email

    **Gathers information on an email address**

    """
    name = "email"
    description = "Gather information on an email address"
    config = None

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_b = subparsers.add_parser('intel', help='Gather Threat Intelligence information on an email address')
        parser_b.add_argument('EMAIL', help='Email address')
        parser_b.set_defaults(subcommand='intel')
        self.parser = parser

    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            if args.subcommand == "intel":
                domains = []
                # TODO
                # MISP
                # HIBP
                # Full Contact / Hunter
                # Google / Yandex / Bing
                # Start with MISP and OTX to get Intelligence Reports
                print('###################### %s ###################' % args.EMAIL)
                # OTX
                # Stuck for now because of https://github.com/AlienVault-OTX/OTX-Python-SDK/issues/41
                #otx_e = plugins['otx'].test_config(conf)
                #if otx_e:
                    #print('[+] Downloading OTX information....')
                    #otx = OTXv2(conf["AlienVaultOtx"]["key"])
                    #res = otx.get_indicator_details_full(IndicatorTypes.EMAIL, unbracket(args.EMAIL))

                # PT
                pt_e = plugins['pt'].test_config(conf)
                if pt_e:
                    print('----------------- Passive Total')
                    client = WhoisRequest(conf['PassiveTotal']['username'], conf['PassiveTotal']['key'])
                    raw_results = client.search_whois_by_field(query=args.EMAIL.strip(), field="email")
                    if "results" in raw_results:
                        if len(raw_results["results"]) == 0:
                            print("Nothing found")
                        else:
                            for res in raw_results["results"]:
                                # Concat all other interesting infos
                                other_infos = []
                                for a in ["admin", "tech", "registrant"]:
                                    if a in res:
                                        for b in ["email", "name", "organization", "telephone"]:
                                            if b in res[a]:
                                                if res[a][b] not in other_infos:
                                                    other_infos.append(res[a][b])
                                print("[%s] %-25s (%s)" % (
                                        res["registered"][:10],
                                        res["domain"],
                                        ', '.join(other_infos)
                                    )
                                )
                    else:
                        print("Nothing found")

                    # Github
                    github_e = plugins['github'].test_config(conf)
                    if github_e:
                        print('----------- Github')
                        g = Github(conf['Github']['token'])
                        res = g.search_code(args.EMAIL)
                        nb = 0
                        for i in res:
                            print('[+] %s' % i.html_url)
                            print(i.decoded_content[:300])
                            print('')
                            nb += 1
                            if nb > 10:
                                break
                        if nb == 0:
                            print("Nothing found")

                    # GPG
                    print('----------- PGP server')

                    res = Pgp.search(args.EMAIL)
                    if len(res):
                        for r in res:
                            print("[+] %s\t%s\t%s %s" % (
                                    r['id'],
                                    r['date'].strftime("%Y-%m-%d"),
                                    r['emails'][0][0],
                                    r['emails'][0][1]
                                )
                            )
                            if len(r['emails']) > 1:
                                for e in r['emails'][1:]:
                                    print("\t\t\t\t\t%s %s" % (e[0], e[1]))
                    else:
                        print("Nothing found")




            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
