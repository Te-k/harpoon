#! /usr/bin/env python
import sys
from harpoon.commands.base import Command
from github import Github


class CommandGithub(Command):
    name = "github"
    description = "Request Github information through the API"
    config = { 'Github': ['token']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='SubCommands')
        parser_a = subparsers.add_parser('search', help='Search in github')
        parser_a.add_argument('--type', '-t',
                choices=['repo', 'code', 'commit', 'issues', 'wikis', 'users'],
                default='code',
                help='Type of data to search')
        parser_a.add_argument('--limit', '-l',
                default='10', type=int,
                help='Result limit')
        parser_a.add_argument('SEARCH')
        parser_a.set_defaults(subcommand='search')
        self.parser = parser

    def run(self, conf, args):
        g = Github(conf['Github']['token'])
        if 'subcommand' in args:
            if args.subcommand == 'search':
                if args.type == 'code':
                    res = g.search_code(args.SEARCH)
                    nb = 0
                    for i in res:
                        print('[+] %s' % i.html_url)
                        print(i.decoded_content[:300])
                        print('')
                        nb += 1
                        if nb > args.limit:
                            sys.exit(0)
                elif args.type == 'repo':
                    res = g.search_repositories(args.SEARCH)
                    nb = 0
                    for i in res:
                        print('[+] %s by %s' % (i.name, i.owner.name))
                        print('\t%s' % i.description)
                        print('\t%s' % i.html_url)
                        print('\t%s' % i.language)
                        print('\t[Watch: %i][Stars: %i][Forks: %i]' % (
                                i.watchers,
                                i.stargazers_count,
                                i.forks_count
                            )
                        )
                        print('')
                        nb += 1
                        if nb > args.limit:
                            sys.exit(0)
                elif args.type == 'commit':
                    # Not yet implemented by PyGithub
                    raise Error('Not yet implemented')
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
