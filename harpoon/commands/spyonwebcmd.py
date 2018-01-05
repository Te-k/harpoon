#! /usr/bin/env python
import argparse
import configparser
import os
import sys
import json
from harpoon.commands.base import Command
from spyonweb import SpyOnWeb, SpyOnWebNotFound, SpyOnWebInvalidToken, SpyOnWebError


class CommandSpyonweb(Command):
    """
    # Spy On Web

    **Queries Spy On Web database http://spyonweb.com/**

    * Search for a domain: `harpoon spyonweb domain example.org`
    * Search for an adsense id: `harpoon spyonweb adsense ID`
    * Search for a Google Analytics id: `harpoon spyonweb analytics ID`
    * Search for an IP address: `harpoon spyonweb ip IP`
    """

    name = "spyonweb"
    description = "Search in SpyOnWeb through the API"
    config = {'SpyOnWeb': ['token']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommands')
        parser_b = subparsers.add_parser('domain', help='Query a domain')
        parser_b.add_argument('DOMAIN', help='Domain to be requested')
        parser_b.add_argument('--raw', '-r', action='store_true',
                help='Print raw list of domains')
        parser_b.set_defaults(subcommand='domain')
        parser_c = subparsers.add_parser('adsense', help='Query an adsense id')
        parser_c.add_argument('ID', help='id to be requested')
        parser_c.add_argument('--raw', '-r', action='store_true',
                help='Print raw list of domains')
        parser_c.set_defaults(subcommand='adsense')
        parser_d = subparsers.add_parser('analytics', help='Query a Google Analytics id')
        parser_d.add_argument('ID', help='id to be requested')
        parser_d.add_argument('--raw', '-r', action='store_true',
                help='Print raw list of domains')
        parser_d.set_defaults(subcommand='analytics')
        parser_e = subparsers.add_parser('ip', help='Query an IP Address')
        parser_e.add_argument('IP', help='IP address to be requested')
        parser_e.add_argument('--raw', '-r', action='store_true',
                help='Print raw list of domains')
        parser_e.set_defaults(subcommand='ip')
        parser_f = subparsers.add_parser('nsdomain', help='Query an Name Server domain')
        parser_f.add_argument('DOMAIN', help='Name Server Domain to be requested')
        parser_f.add_argument('--raw', '-r', action='store_true',
                help='Print raw list of domains')
        parser_f.set_defaults(subcommand='nsdomain')
        parser_g = subparsers.add_parser('nsip', help='Query a Name Server IP address')
        parser_g.add_argument('IP', help='Name Server IP Address to be requested')
        parser_g.add_argument('--raw', '-r', action='store_true',
                help='Print raw list of domains')
        parser_g.set_defaults(subcommand='nsip')
        self.parser = parser


    def run(self, conf, args, plugins):
        if hasattr(args, 'subcommand'):
            s = SpyOnWeb(conf['SpyOnWeb']['token'])
            if args.subcommand == 'domain':
                try:
                    res = s.summary(args.DOMAIN)
                except SpyOnWebNotFound:
                    print('Domain not found')
                except SpyOnWebInvalidToken:
                    print('Invalid configuration')
                except SpyOnWebError as e:
                    print('Weird error: %s' % e.message)
                else:
                    if args.raw:
                        print(json.dumps(res, sort_keys=True, indent=4))
                    else:
                        print('--------------- %s -----------------' % args.DOMAIN)
                        if 'ip' in res:
                            print('IP:')
                            for i in res['ip']:
                                print('-%s: %i entries' % (i, res['ip'][i]))
                        if 'adsense' in res:
                            print('AdSense:')
                            for i in res['adsense']:
                                print('-%s: %i entries' % (i, res['adsense'][i]))
                        if 'analytics' in res:
                            print('Analytics:')
                            for i in res['analytics']:
                                print('-%s: %i entries' % (i, res['analytics'][i]))
                        if 'dns_servers' in res:
                            print('DNS Servers:')
                            for i in res['dns_servers']:
                                print('-%s: %i entries' % (i, res['dns_servers'][i]))
            elif args.subcommand == 'adsense':
                try:
                    res = s.adsense(args.ID)
                except SpyOnWebNotFound:
                    print('Adsense id not found')
                except SpyOnWebInvalidToken:
                    print('Invalid configuration')
                except SpyOnWebError as e:
                    print('Weird error: %s' % e.message)
                else:
                    if args.raw:
                        for i in res['items']:
                            print(i)
                    else:
                        print('--------------- %s -----------------' % args.ID)
                        print('Fetched %i domains over %i' % (res['fetched'], res['found']))
                        for i in res['items']:
                            print('-%s (%s)' % (i, res['items'][i]))
            elif args.subcommand == 'analytics':
                try:
                    res = s.analytics(args.ID)
                except SpyOnWebNotFound:
                    print('Analytic id not found')
                except SpyOnWebInvalidToken:
                    print('Invalid configuration')
                except SpyOnWebError as e:
                    print('Weird error: %s' % e.message)
                else:
                    if args.raw:
                        for i in res['items']:
                            print(i)
                    else:
                        print('--------------- %s -----------------' % args.ID)
                        print('Fetched %i domains over %i' % (res['fetched'], res['found']))
                        for i in res['items']:
                            print('-%s (%s)' % (i, res['items'][i]))
            elif args.subcommand == 'ip':
                try:
                    res = s.ip(args.IP)
                except SpyOnWebNotFound:
                    print('IP address not found')
                except SpyOnWebInvalidToken:
                    print('Invalid configuration')
                except SpyOnWebError as e:
                    print('Weird error: %s' % e.message)
                else:
                    if args.raw:
                        for i in res['items']:
                            print(i)
                    else:
                        print('--------------- %s -----------------' % args.IP)
                        print('Fetched %i domains over %i' % (res['fetched'], res['found']))
                        for i in res['items']:
                            print('-%s (%s)' % (i, res['items'][i]))
            elif args.subcommand == 'nsdomain':
                try:
                    res = s.nameserver_domain(args.DOMAIN)
                except SpyOnWebNotFound:
                    print('Name Server domain not found')
                except SpyOnWebInvalidToken:
                    print('Invalid configuration')
                except SpyOnWebError as e:
                    print('Weird error: %s' % e.message)
                else:
                    if args.raw:
                        for i in res['items']:
                            print(i)
                    else:
                        print('--------------- %s -----------------' % args.DOMAIN)
                        print('Fetched %i domains over %i' % (res['fetched'], res['found']))
                        for i in res['items']:
                            print('-%s (%s)' % (i, res['items'][i]))
            elif args.subcommand == 'nsip':
                try:
                    res = s.nameserver_ip(args.IP)
                except SpyOnWebNotFound:
                    print('Name Server IP not found')
                except SpyOnWebInvalidToken:
                    print('Invalid configuration')
                except SpyOnWebError as e:
                    print('Weird error: %s' % e.message)
                else:
                    if args.raw:
                        for i in res['items']:
                            print(i)
                    else:
                        print('--------------- %s -----------------' % args.IP)
                        print('Fetched %i domains over %i' % (res['fetched'], res['found']))
                        for i in res['items']:
                            print('-%s (%s)' % (i, res['items'][i]))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
