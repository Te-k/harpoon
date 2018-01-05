#! /usr/bin/env python
import sys
from harpoon.commands.base import Command
from github import Github, UnknownObjectException


class CommandGithub(Command):
    """
    # Github

    **Request Github API**

    * Get information on a repository: `harpoon github repo kneufeld/consolemd`
    * Search for information in Github code: `harpoon github search randhome.io`
    * Search for information in Github repo: `harpoon github search -t repo harpoon`
    """
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
        parser_b = subparsers.add_parser('repo', help='Information on a github repository')
        parser_b.add_argument('REPOSITORY')
        parser_b.add_argument('-o', '--only-emails', action="store_true", help="Only list emails of committers")
        parser_b.set_defaults(subcommand='repo')

        self.parser = parser

    def run(self, conf, args, plugins):
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
                    raise Exception('Not yet implemented')
            elif args.subcommand == "repo":
                # clean input
                if args.REPOSITORY.startswith("https://github.com"):
                    rep_name = args.REPOSITORY[19:]
                else:
                    rep_name = args.REPOSITORY
                if rep_name.endswith(".git"):
                    rep_name = rep_name[:-4]
                repo = g.get_repo(rep_name)
                # Check if found
                try:
                    idd = repo.id
                except UnknownObjectException:
                    print("Repository not found")
                    return
                if args.only_emails:
                    # FIXME: really slow
                    committers = set()
                    for c in repo.get_commits():
                        if c.committer:
                            if c.committer.email:
                                committers.add(c.committer.email)
                    for c in committers:
                        print(c)
                else:
                    print("-Name: %s" % repo.full_name)
                    print("-Owner: %s %s" % (repo.owner.login, repo.owner.email))
                    print("-Language: %s" % repo.language)
                    print("-%i Watchers / %i Stars / %i Forks" % (
                            repo.watchers,
                            repo.stargazers_count,
                            repo.forks_count
                        )
                    )
                    # FIXME: really slow
                    committers = {}
                    for c in repo.get_commits():
                        if c.committer:
                            if c.committer.email:
                                if c.committer.email in committers:
                                    committers[c.committer.email] += 1
                                else:
                                    committers[c.committer.email] = 1
                    print("-Committers:")
                    for committer in sorted(committers.items()):
                        print("\t%s %i" % ( committer[0], committer[1]))


            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
