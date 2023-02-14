#! /usr/bin/env python
import json
import sys

from harpoon.commands.base import Command
from harpoon.lib.certspotter import CertSpotter, CertSpotterError
from harpoon.lib.utils import json_serial, unbracket


class CommandCertSpotter(Command):
    """
    # Cert Spotter Command

    Search in Certificate Transparency database Cert Spotter https://sslmate.com/certspotter.
    Only current certificates can be searched without paid plan

    * Search certificates for a domain : `harpoon certspotter search DOMAIN`
    * Search certificates for a domain and its subdomains : `harpoon certspotter search -s DOMAIN`
    """
    name = "certspotter"
    description = "Get certificates from https://sslmate.com/certspotter"
    config = None

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('search', help='Search certificates for a domain')
        parser_a.add_argument('DOMAIN', help='domain')
        parser_a.add_argument(
            '--subdomains', '-s',
            help='Search for the domain and its subdomains', action='store_true')
        parser_a.set_defaults(subcommand='search')
        self.parser = parser

    def run(self, args, plugins):
        try:
            cs = CertSpotter(self._config_data['CertSpotter']['key'])
        except KeyError:
            cs = CertSpotter()

        if 'subcommand' in args:
            if args.subcommand == 'search':
                try:
                    res = cs.search(unbracket(args.DOMAIN), include_subdomains=args.subdomains)
                except CertSpotterError:
                    print("Error with the API, likely because you need a paid plan to search expired certs.")
                    print("Check censys or crtsh plugins instead")
                    sys.exit(1)
                else:
                    print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
