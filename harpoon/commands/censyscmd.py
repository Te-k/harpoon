#! /usr/bin/env python
import sys
import json
import censys
from censys import ipv4, certificates
from harpoon.commands.base import Command


class CommandCensys(Command):
    """
    # Censys plugin

    **Query Censys.io API**

    * Query information on an IP: `harpoon censys ip 172.217.2.174`
    * Query a certificate: `harpoon censys certificate ID`
    * Search for subdomains based on certificates : `harpoon censys subdomains DOMAIN`
    """
    name = "censys"
    description = "Request information from Censys database (https://censys.io/)"
    config = {'Censys': ['id', 'secret']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('ip', help='Get information on an IP address')
        parser_a.add_argument('IP', help='IP to be searched')
        parser_a.add_argument('--search', '-s', action='store_true',
                help='Search for this value in IP infos')
        parser_a.set_defaults(subcommand='ip')
        parser_b = subparsers.add_parser('cert', help='Get information on a certificate')
        parser_b.add_argument('ID', help='ID of the certificate')
        parser_b.set_defaults(subcommand='cert')
        parser_c = subparsers.add_parser('subdomains', help='Query certificates for a domain looking for subdomains')
        parser_c.add_argument('DOMAIN', help='Domain')
        parser_c.add_argument('--verbose', '-v', action='store_true',
                help='Verbose')
        parser_c.set_defaults(subcommand='subdomains')
        parser_d = subparsers.add_parser('account', help='Get account information including quota')
        parser_d.set_defaults(subcommand='account')
        self.parser = parser

    def get_subdomains(self, conf, domain, verbose, only_sub=False):
        """
        Inspired from https://github.com/appsecco/the-art-of-subdomain-enumeration/blob/master/censys_subdomain_enum.py
        """
        api = certificates.CensysCertificates(conf['Censys']['id'], conf['Censys']['secret'])
        subdomains = set()
        for cert in api.search(domain):
            if cert['parsed.subject_dn'].endswith(domain):
                if verbose:
                    print('Certificate : %s - %s' % (
                        cert['parsed.subject_dn'],
                        cert['parsed.fingerprint_sha256']
                        )
                    )
                subdomains.add(cert['parsed.subject_dn'].split('CN=')[1])
                c = api.view(cert['parsed.fingerprint_sha256'])
                try:
                    for name in c['parsed']['names']:
                        if only_sub:
                            if name.endswith(domain):
                                subdomains.add(name)
                        else:
                            subdomains.add(name)
                except KeyError:
                    pass

        return subdomains

    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            if args.subcommand == 'ip':
                api = ipv4.CensysIPv4(conf['Censys']['id'], conf['Censys']['secret'])
                if args.search:
                    res = api.search(args.IP)
                    for r in res:
                        if len(r['ip']) > 11:
                            print("[+] %s\t[Location: %s] [Ports: %s]" % (
                                    r['ip'],
                                    r['location.country'],
                                    " ".join(r['protocols'])
                                )
                            )
                        else:
                            print("[+] %s\t\t[Location: %s] [Ports: %s]" % (
                                    r['ip'],
                                    r['location.country'],
                                    " ".join(r['protocols'])
                                )
                            )
                else:
                    try:
                        ip = api.view(args.IP)
                        print(json.dumps(ip, sort_keys=True, indent=4, separators=(',', ': ')))
                    except censys.base.CensysNotFoundException:
                        print('IP not found')
            elif args.subcommand == 'cert':
                try:
                    c = certificates.CensysCertificates(conf['Censys']['id'], conf['Censys']['secret'])
                    res = c.view(args.ID)
                except censys.base.CensysNotFoundException:
                    print("Certificate not found")
                else:
                    print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': ')))
            elif args.subcommand == 'subdomains':
                subdomains = self.get_subdomains(conf, args.DOMAIN, args.verbose)
                for d in subdomains:
                    print(d)
            elif args.subcommand == 'account':
                api = ipv4.CensysIPv4(conf['Censys']['id'], conf['Censys']['secret'])
                # Gets account data
                account = api.account()
                print(json.dumps(account, sort_keys=True, indent=4))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        if type == "ip":
            print("[+] Checking Censys...")
            api = ipv4.CensysIPv4(conf['Censys']['id'], conf['Censys']['secret'])
            try:
                ip = api.view(query)
                for port in ip["ports"]:
                    data["ports"].append({
                        "port": port,
                        "info": "",
                        "source": "Censys"
                    })
            except censys.base.CensysNotFoundException:
                pass
