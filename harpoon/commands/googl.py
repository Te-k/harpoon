#! /usr/bin/env python
import sys
import json
from harpoon.commands.base import Command
from harpoon.lib.googl import GoogleShortener

class CommandGoogl(Command):
    """
    # Goo.gl URL shortener plugin

    * Search for a hash: `harpoon googl -H 12445`
    * Search for a list of hash from a file: `harpoon googl -f FILE`
    """
    name = "googl"
    description = "Requests Google url shortener API"
    config = {'Googl': ['token']}

    def add_arguments(self, parser):
        parser.add_argument('--hash', '-H', help='HASH of a link')
        parser.add_argument('--file', '-f', help='File containing list of hashes')

    def run(self, conf, args, plugins):
        if 'Googl' not in conf:
            print('Invalid configuration file, quitting...')
            sys.exit(1)
        if 'token' not in conf['Googl']:
            print('Invalid configuration file, quitting...')
            sys.exit(1)
        go = GoogleShortener(conf['Googl']['token'])
        if args.hash:
            print(json.dumps(go.get_analytics(args.hash), sort_keys=True, indent=4, separators=(',', ':')))
        elif args.file:
            with open(args.file, 'r') as f:
                data = f.read().split()

            print("Date;Status;Short URL;Long URL;Analytics;Short URL Clicks;Long URL Clicks")
            for d in data:
                res = go.get_analytics(d.strip())
                print("%s;%s;%s;%s;https://goo.gl/#analytics/goo.gl/%s/all_time;%s;%s" %
                    (
                        res.get("created", ""),
                        res.get("status", ""),
                        res["id"],
                        res.get("longUrl", ""),
                        res["id"][-6:],
                        res.get("analytics", {}).get("allTime", {}).get("shortUrlClicks", ""),
                        res.get("analytics", {}).get("allTime", {}).get("longUrlClicks", ""),
                    )
                )
        else:
            print("Please provide a file (-f) or a hash (-H)")
