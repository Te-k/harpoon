#! /usr/bin/env python
import os
import sys
import json
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket, json_serial
from harpoon.lib.certspotter import CertSpotter, CertSpotterError

class CommandCertSpotter(Command):
    """
    # Cert Spotter Command

    Search in Certificate Transparency database Cert Spotter https://sslmate.com/certspotter. Only actual certificate can be searched without paid plan

    * Search for certificates of a domain : `harpoon certspotter search DOMAIN`
    * Search for certificates of a domain including expired certificates : `harpoon certspotter search DOMAIN -a` (paid plans only)
    * Get information on a certificate: `harpoon certspotter cert SHA256`

    """
    name = "certspotter"
    description = "Get certificates from https://sslmate.com/certspotter"
    config = None

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('search', help='Search certificates for a domain')
        parser_a.add_argument('DOMAIN', help='domain')
        parser_a.add_argument('--all', '-a', help='List all certificates including expired one too (API key needed)', action='store_true')
        parser_a.set_defaults(subcommand='search')
        parser_b = subparsers.add_parser('cert', help='Show information on a certificate')
        parser_b.add_argument('SHA256', help='Sha256 of the certificate')
        parser_b.set_defaults(subcommand='cert')
        self.parser = parser

    def run(self, conf, args, plugins):
        try:
            cs = CertSpotter(conf['CertSpotter']['key'])
        except KeyError:
            cs = CertSpotter()

        if 'subcommand' in args:
            if args.subcommand == 'search':
                if args.all:
                    if cs.authenticated:
                        try:
                            res = cs.list(unbracket(args.DOMAIN), expired=True)
                        except CertSpotterError:
                            print("Error with the API, likely because you need a paid plan to search expired certs. Check censys or crtsh plugins instead")
                            sys.exit(1)
                    else:
                        print("API key needed for expired certificated")
                        sys.exit(1)
                else:
                    res = cs.list(unbracket(args.DOMAIN))
                print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))
            elif args.subcommand == "cert":
                res = cs.get_cert(args.SHA256)
                print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': '), default=json_serial))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
