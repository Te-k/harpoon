#! /usr/bin/env python
import sys
import json
from harpoon.commands.base import Command
from pypermacc import Permacc, PermaccError

class CommandPemacc(Command):
    """
    # Perma.cc plugin

    **Query the permacc API**

    * Save an url : harpoon permacc save URL
    * See last 10 urls saved : harpoon permacc list
    * Download an archive for an url: harpoon permacc download Y6JJ-TDUJ
    * Get information on an archive : harpoon permacc info Y6JJ-TDUJ
    """
    name = "permacc"
    description = "Request Perma.cc information through the API"
    config = { 'Permacc': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('save', help='Save an url in perma.cc')
        parser_a.add_argument('URL', help='Url')
        parser_a.set_defaults(subcommand='save')
        parser_b = subparsers.add_parser('info', help='Show information on a saved page')
        parser_b.add_argument('GUID', help='Guid (like Y6JJ-TDUJ)')
        parser_b.set_defaults(subcommand='info')
        parser_c = subparsers.add_parser('download', help='Download the WARC archive')
        parser_c.add_argument('GUID', help='Guid (like Y6JJ-TDUJ)')
        parser_c.add_argument('--output', '-o', default='webpage.warc', help='Name of the file downloaded')
        parser_c.set_defaults(subcommand='download')
        parser_d = subparsers.add_parser('list', help='List pages archived by your account')
        parser_d.set_defaults(subcommand='list')
        self.parser = parser

    def run(self, conf, args, plugins):
        permacc = Permacc(conf['Permacc']['key'])
        if 'subcommand' in args:
            if args.subcommand == 'save':
                try:
                    saved = permacc.archive_create(args.URL)
                    print('Saved: https://perma.cc/%s - %s' % (saved['guid'], saved['guid']))
                except PermaccError:
                    print('Failed')
            elif args.subcommand == 'download':
                warc = permacc.archive_download(args.GUID)
                if args.output == 'webpage.warc':
                    outputname = args.GUID + '.warc'
                else:
                    outputname = args.output
                with open(outputname, "wb") as f:
                    f.write(warc)
                print('Archive saved as %s' % outputname)
            elif args.subcommand == 'info':
                infos = permacc.archive_detail(args.GUID)
                print(json.dumps(infos, sort_keys=False, indent=4))
            elif args.subcommand == 'list':
                archives = permacc.user_archives()
                print('Last 10 pages:')
                for o in archives['objects']:
                    print("- https://perma.cc/%s %s" % (o['guid'], o['url']))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
