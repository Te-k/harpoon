#! /usr/bin/env python
from harpoon.commands.base import Command
from harpoon.commands.censyscmd import CommandCensys
from harpoon.lib.utils import unbracket
from passivetotal.libs.enrichment import EnrichmentRequest
from virus_total_apis import PublicApi, PrivateApi
from censys.base import CensysRateLimitExceededException


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
        parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
        parser.add_argument(
            '--source', '-s',
            choices=['all', 'censys', 'pt', 'vt'],
            default='all',
            help='Source of the research'
        )
        self.parser = parser

    def censys_certs(self, domain, conf, verbose):
        censys_cmd = CommandCensys()
        print('## Searching through Censys certificates')
        subdomains = censys_cmd.get_subdomains(
            conf,
            domain,
            verbose,
            only_sub=True
        )
        for d in subdomains:
            print(d)

    def pt(self, domain, conf, verbose):
        client = EnrichmentRequest(
            conf["PassiveTotal"]["username"],
            conf["PassiveTotal"]['key']
        )
        print('## Searching subdomains in Passive Total')
        res = client.get_subdomains(query=domain)
        for d in res['subdomains']:
            print('%s.%s' % (d, domain))

    def vt(self, domain, conf, verbose):
        print('## Searching subdomains in Virus Total')
        if conf["VirusTotal"]["type"] == "public":
            vt = PublicApi(conf["VirusTotal"]["key"])
        else:
            vt = PrivateApi(conf["VirusTotal"]["key"])
        res = vt.get_domain_report(domain)
        try:
            for d in res['results']['subdomains']:
                print(d)
        except KeyError:
            pass

    def run(self, conf, args, plugins):
        if args.source == 'all':
            # Search subdomains through a search in Censys certificates
            if plugins['censys'].test_config(conf):
                try:
                    self.censys_certs(unbracket(args.DOMAIN), conf, args.verbose)
                except CensysRateLimitExceededException:
                    print('Quota exceeded!')
            # Get subdomains through passive total
            if plugins['pt'].test_config(conf):
                self.pt(unbracket(args.DOMAIN), conf, args.verbose)
            if plugins['vt'].test_config(conf):
                self.vt(unbracket(args.DOMAIN), conf, args.verbose)

        elif args.source == 'censys':
            if plugins['censys'].test_config(conf):
                try:
                    self.censys_certs(unbracket(args.DOMAIN), conf, args.verbose)
                except CensysRateLimitExceededException:
                    print('Quota exceeded!')
            else:
                print('Please configure your Censys credentials')
        elif args.source == 'pt':
            if plugins['pt'].test_config(conf):
                self.pt(unbracket(args.DOMAIN), conf, args.verbose)
            else:
                print('Please configure your Passive Total credentials')
        elif args.source == 'vt':
            if plugins['vt'].test_config(conf):
                self.vt(unbracket(args.DOMAIN), conf, args.verbose)
            else:
                print('Please configure your VirusTotal credentials')
