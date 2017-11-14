#! /usr/bin/env python
import sys
from harpoon.commands.base import Command
from harpoon.lib.bitly import Bitly, Link

class CommandBitly(Command):
    name = "bitly"
    description = "Request bit.ly information through the API"

    def add_arguments(self, parser):
        parser.add_argument('--hash', '-H', help='HASH of a link')
        parser.add_argument('--file', '-f', help='File containing list of hashes')

    def run(self, conf, args):
        if 'Bitly' not in conf and 'token' not in conf['Bitly']:
            print('Invalid configuration file, quitting...')
            sys.exit(1)
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
            print("Please provide a hash or a file")


