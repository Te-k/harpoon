#! /usr/bin/env python
import json
from harpoon.commands.base import Command
from harpoon.lib.opencage import OpenCageGeocode


class CommandOpenCageInfo(Command):
    """
    # OpenCage plugin

    **Query OpenCage geocoder API**

    * Forward Geocoding : `harpoon opencage search QUERY`
    * Reverse Geocoding : `harpoon opencage reverse LATITUDE LONGITUDE`
    """
    name = "opencage"
    description = "Forward/Reverse Geocoding using OpenCage"
    config = {'OpenCage': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('search', help='Search coordinates of an address or location')
        parser_a.add_argument('QUERY', help='Query (Address, Location, ...)')
        parser_a.set_defaults(subcommand='search')
        parser_b = subparsers.add_parser('reverse', help='Request the nearest address for coordinates')
        parser_b.add_argument('LATITUDE', help='Latitude')
        parser_b.add_argument('LONGITUDE', help='Longitude')
        parser_b.set_defaults(subcommand='reverse')
        self.parser = parser

    def run(self, conf, args, plugins):
        geocoder = OpenCageGeocode(key=conf['OpenCage']['key'])
        if 'subcommand' in args:
            if args.subcommand == 'search':
                try:
                    infos = geocoder.geocode(args.QUERY)
                except OpenCageError:
                    print("Invalid request")
                else:
                    print(json.dumps(infos,  sort_keys=True, indent=4, separators=(',', ': ')))
            elif args.subcommand == 'reverse':
                try:
                    infos = geocoder.reverse_geocode(args.LATITUDE, args.LONGITUDE)
                except OpenCageError:
                    print("Invalid request")
                else:
                    print(json.dumps(infos,  sort_keys=True, indent=4, separators=(',', ': ')))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
