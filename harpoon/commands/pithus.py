import json

from harpoon.commands.base import Command
from harpoon.lib.pithus import Pithus


class CommandPithus(Command):
    """
    # Pithus

    Queries the Pithus API

    * Query the database: `harpoon pithus report SHA256`
    * Query the status of an upload: `harpoon pithus status SHA256`
    * Upload a sample: `harpoon pithus upload FILEPATH`
    * Search the database: `harpoon pithus search SHA256`
    * Advanced search example: `harpoon pithus search 'domains: *google.com && permissions: *INTERNET'`

    See: beta.pithus.org for documentation on the search options
    """
    name = "pithus"
    description = "Search Pithus database for submitted APKs"
    config = {"Pithus": ["key", "url"]}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')

        # get request for a report
        parser_a = subparsers.add_parser(
            'report', help='Retrieve a report from Pithus')
        parser_a.add_argument('SHA256', help='Hash of the sample')
        parser_a.add_argument(
            "--json", "-j", action="store_true",
            help="Show raw JSON info")
        parser_a.set_defaults(subcommand='report')

        # get request for the status of the analysis of a report
        parser_b = subparsers.add_parser(
            'status', help='Retrieve the status of tasks for a given report')
        parser_b.add_argument(
            "--json", "-j", action="store_true",
            help="Show raw JSON info")
        parser_b.add_argument('SHA256', help='Hash of the sample')
        parser_b.set_defaults(subcommand='status')

        # post request to upload a sample
        parser_c = subparsers.add_parser(
            'upload', help='Upload a sample on Pithus')
        parser_c.add_argument(
            'FILEPATH', help='Upload a sample to Pithus, provide a filepath')
        parser_c.set_defaults(subcommand='upload')

        # post request for advanced search
        parser_d = subparsers.add_parser('search', help='Search in Pithus')
        parser_d.add_argument('QUERY', help='Search query, default is SHA256')
        parser_d.add_argument(
            "--json", "-j", action="store_true",
            help="Show raw JSON info")
        parser_d.set_defaults(subcommand='search')
        self.parser = parser

    def run(self, args, plugins):
        if 'subcommand' not in args:
            self.parser.print_help()
        else:
            pithus = Pithus(self._config_data['Pithus'])

            if args.subcommand == 'report':
                res = pithus.report(args.SHA256)
                if args.json:
                    print(json.dumps(res, indent=4))
                else:
                    pithus.pretty_print(res, "report")
            elif args.subcommand == 'status':
                res = pithus.status(args.SHA256)
                if args.json:
                    print(json.dumps(res, indent=4))
                else:
                    pithus.pretty_print(res, "status")
            elif args.subcommand == 'upload':
                with open(args.FILEPATH, "rb") as f:
                    data = f.read()
                pithus.upload(data)
            elif args.subcommand == 'search':
                res = pithus.search(args.QUERY)
                if args.json:
                    print(json.dumps(res, indent=4))
                else:
                    pithus.pretty_print(res, "search")
            else:
                self.parser.print_help()

    # TODO : intel
