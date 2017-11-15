#! /usr/bin/env python
import sys
import json
from harpoon.commands.base import Command
from harpoon.lib.googl import GoogleShortener

class CommandGoogl(Command):
    name = "googl"
    description = "Requests Google url shortener API"
    config = {'Googl': ['token']}

    def add_arguments(self, parser):
        parser.add_argument('--hash', '-H', help='HASH of a link')
        parser.add_argument('--file', '-f', help='File containing list of hashes')

    def run(self, conf, args):
        if 'Googl' not in conf:
            print('Invalid configuration file, quitting...')
            sys.exit(1)
        if 'token' not in conf['Googl']:
            print('Invalid configuration file, quitting...')
            sys.exit(1)
        go = GoogleShortener(config['Googl']['token'])
        if args.hash:
            print(json.dumps(go.get_analytics(args.hash), sort_keys=True, indent=4, separators=(',', ':')))
        else:
            f = open(args.file, 'r')
            data = f.read().split()
            f.close()
            print("Date;Short URL;Long URL;Analytics;Short URL Clicks;Long URL Clicks")
            for d in data:
                res = go.get_analytics(d.strip())
                print("%s;%s;%s;https://goo.gl/#analytics/goo.gl/%s/all_time;%s;%s" %
                    (
                        res["created"],
                        res["id"],
                        res["longUrl"],
                        res["id"][-6:],
                        res["analytics"]["allTime"]["shortUrlClicks"],
                        res["analytics"]["allTime"]["longUrlClicks"]
                    )
                )
