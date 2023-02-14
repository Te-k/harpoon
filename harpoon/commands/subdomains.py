#! /usr/bin/env python
from censys.common.exceptions import CensysRateLimitExceededException
from passivetotal.libs.enrichment import EnrichmentRequest
from virus_total_apis import PrivateApi, PublicApi

from harpoon.commands.base import Command
from harpoon.commands.censyscmd import CommandCensys
from harpoon.lib.utils import unbracket


class CommandSubdomains(Command):
    """
    # Subdomains plugin

    **Research subdomains for a domain**

    * Search for subdomains : `harpoon subdomains DOMAIN`

    """
    name = "subdomains"
    description = "Research subdomains of a domain"

    def add_arguments(self, parser):
        parser.add_argument('DOMAIN', help='Domain')
        parser.add_argument('--verbose', '-v',
                            action='store_true', help='Verbose mode')
        parser.add_argument(
            '--source', '-s',
            choices=['all', 'censys', 'pt', 'vt'],
            default='all',
            help='Source of the research'
        )
        self.parser = parser

    def censys_certs(self, domain, conf, verbose):
        censys_cmd = CommandCensys()
        print('[+] Searching through Censys certificates')
        subdomains = censys_cmd.get_subdomains(
            conf,
            domain,
            verbose,
        )
        return subdomains

    def pt(self, domain, conf, verbose):
        client = EnrichmentRequest(
            conf["PassiveTotal"]["username"],
            conf["PassiveTotal"]['key']
        )
        print('[+] Searching subdomains in Passive Total')
        res = client.get_subdomains(query=domain)
        cleaned = []
        for sub in res['subdomains']:
            cleaned.append(sub+'.'+domain)

        return cleaned

    def vt(self, domain, conf, verbose):
        print('[+] Searching subdomains in Virus Total')
        if conf["VirusTotal"]["type"] == "public":
            vt = PublicApi(conf["VirusTotal"]["key"])
        else:
            vt = PrivateApi(conf["VirusTotal"]["key"])
        res = vt.get_domain_report(domain)

        if res['response_code'] == 204:
            print("VT quota exceeded!")
            return []
        else:
            return res['results']['subdomains']

    def prepare_data(self, subdomains=dict, data=dict, source=str):
        if len(subdomains) > 0:
            for domain in subdomains:
                data['subdomains'].append(
                    {"source": source, "domain": domain})

    def intel(self, type, query, data):
        if type == "domain":
            try:
                # subdomains = self.censys_certs(unbracket(query), self._confif_data, True)
                # self.prepare_data(subdomains, data, "Censys")
                pass

            except CensysRateLimitExceededException:
                print('Censys quota exceeded!')
            # subdomains = self.pt(unbracket(query), conf, True)
            # self.prepare_data(subdomains, data, "PassiveTotal")
            # subdomains = self.vt(unbracket(query), conf, True)
            # self.prepare_data(subdomains, data, "VirusTotal")

        else:
            pass

    def run(self, conf, args, plugins):
        if args.source == 'all':
            # Search subdomains through a search in Censys certificates
            if plugins['censys'].test_config(conf):
                try:
                    subs = self.censys_certs(
                        unbracket(args.DOMAIN), conf, args.verbose)
                    for sub in subs:
                        print(sub)
                except CensysRateLimitExceededException:
                    print('Quota exceeded!')
            if plugins['pt'].test_config(conf):
                subs = self.pt(unbracket(args.DOMAIN), conf, args.verbose)
                for sub in subs:
                    print(sub)
            if plugins['vt'].test_config(conf):
                subs = self.vt(unbracket(args.DOMAIN), conf, args.verbose)
                for sub in subs:
                    print(sub)

        elif args.source == 'censys':
            if plugins['censys'].test_config(conf):
                try:
                    subs = self.censys_certs(unbracket(args.DOMAIN),
                                             conf, args.verbose)
                    for sub in subs:
                        print(sub)
                except CensysRateLimitExceededException:
                    print('Quota exceeded!')
            else:
                print('Please configure your Censys credentials')
        elif args.source == 'pt':
            if plugins['pt'].test_config(conf):
                subs = self.pt(unbracket(args.DOMAIN), conf, args.verbose)
                for sub in subs:
                    print(sub)
            else:
                print('Please configure your Passive Total credentials')
        elif args.source == 'vt':
            if plugins['vt'].test_config(conf):
                subs = self.vt(unbracket(args.DOMAIN), conf, args.verbose)
                for sub in subs:
                    print(sub)
            else:
                print('Please configure your VirusTotal credentials')
