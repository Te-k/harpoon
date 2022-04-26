import json

from harpoon.commands.base import Command
from harpoon.lib.pithus import Pithus, PithusError


class CommandPithus(Command):
    """
    # Pithus

    Queries the Pithus API 

    * Query the database: `harpoon pithus search SHA256`
    * Advanced query: `harpoon pithus search 'permissions: *INTERNET'`

    See: beta.pithus.org for documentation on the search options
    """
    name = "pithus"
    description = "Search Pithus database for submitted APKs"

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')

        # get request for a report
        parser_a = subparsers.add_parser('report', help='Retrieve a report from Pithus')
        parser_a.add_argument('SHA256', help='Hash of the sample')
        parser_a.set_defaults(subcommand='report')

        # get request for the status of the analysis of a report
        parser_b = subparsers.add_parser('status', help='Retrieve the status of tasks for a given report')
        parser_b.add_argument('SHA256', help='Hash of the sample')
        parser_b.set_defaults(subcommand='status')

        # post request to upload a sample
        parser_c = subparsers.add_parser('upload', help='Upload a sample on Pithus')
        parser_c.add_argument('SAMPLE', help='Upload a sample to Pithus')
        parser_c.set_defaults(subcommand='upload')

        # post request for advanced search
        parser_d = subparsers.add_parser('search', help='Search in Pithus')
        parser_d.add_argument('QUERY', help='Search query, default is SHA256')
        parser_d.set_defaults(subcommand='search')
        self.parser = parser

    def run(self, conf, args, plugins):
        if 'subcommand' not in args:
            self.parser.print_help()
        else:
            key = conf['Pithus']['key'] 
            if key == '':
                PithusError("Missing token, visit beta.pithus.org/hunting to retrieve it")
            else:
                pithus = Pithus(conf['Pithus']['key'])

            if args.subcommand == 'report':
                pithus.report(args.SHA256)
            elif args.subcommand == 'status':
                pithus.status(args.SHA256)
            elif args.subcommand == 'upload':
                pithus.upload(args.SAMPLE)
            elif args.subcommand == 'search':
                pithus.search(args.QUERY)
            else:
                self.parser.print_help()

