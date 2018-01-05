#! /usr/bin/env python
import sys
from harpoon.commands.base import Command
from harpoon.lib.bitly import Bitly, Link

class CommandBitly(Command):
    """
    # Bit.ly plugin

    **Query bit.ly API**

    * Check a has information: `harpoon bitly -H 1234`
    * Check multiple hashes from a file: `harpoon bitly -f hash.csv`
    """
    name = "bitly"
    description = "Request bit.ly information through the API"
    config = { 'Bitly': ['token']}

    def add_arguments(self, parser):
        parser.add_argument('--hash', '-H', help='HASH of a link')
        parser.add_argument('--file', '-f', help='File containing list of hashes')
        self.parser = parser

    def run(self, conf, args, plugins):
        bitly = Bitly(access_token=conf['Bitly']["token"])
        if args.hash:
            link = Link(bitly, args.hash)
            link.pprint()
        elif args.file:
            f = open(args.file, 'r')
            data = f.read().split()
            print("Date;Short URL;Long URL;Analytics;Aggregate;Aggregate Hash;User;Short URL Clicks;Long URL Clicks")
            for d in data:
                if d.strip() != "":
                    link = Link(bitly, d)
                    print("%s;%s;%s;%s;%s;%s;%s;%i;%i" % (
                            link.timestamp.strftime("%m/%d/%Y %H:%M:%S"),
                            link.short_url,
                            link.long_url,
                            link.short_url + "+",
                            link.hash if link.is_aggregate else link.aggregate.hash,
                            "Yes" if link.is_aggregate else "No",
                            link.user_hash,
                            link.clicks,
                            link.clicks if link.is_aggregate else link.aggregate.clicks
                        )
                    )
        else:
            self.parser.print_help()
