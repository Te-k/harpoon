#! /usr/bin/env python
import sys
import requests
from harpoon.commands.base import Command
from harpoon.lib.google import Google
from harpoon.lib.yandex import Yandex
from harpoon.lib.archiveis import ArchiveIs
from harpoon.lib.archiveorg import ArchiveOrg
from harpoon.lib.bing import Bing
from harpoon.lib.utils import unbracket


class CommandCache(Command):
    """
    # Cache

    **Check if a page was cached by archive websites, and download cached page**
    Supported platforms for now: Yandex, Google, Archive.is, Archive.org, Bing


    * Check if a page was archived: `harpoon cache https://www.oreilly.com/'`
    * Download a cached page: `harpoon cache -s google -D https://www.oreilly.com/`
    """
    name = "cache"
    description = "Requests webpage cache from different sources"

    def add_arguments(self, parser):
        parser.add_argument('URL', help='URL of the cache')
        parser.add_argument(
            '--source', '-s',
            choices=['all', 'google', 'yandex', 'webarchive', 'archiveis', 'bing'],
            default='all',
            help='Source of the cache'
        )
        parser.add_argument('--dump', '-D', action='store_true', help='Dump data')
        self.parser = parser

    def run(self, conf, args, plugins):
        url = unbracket(args.URL)
        if args.source == 'all':
            if args.dump:
                print("Please specify the source to dump the data")
                sys.exit(1)
            # Google
            google = Google.cache(url)
            if google['success']:
                if 'date' in google:
                    print('Google: FOUND %s (%s)' % (
                        google['cacheurl'],
                        google['date']
                    ))
                else:
                    print('Google: FOUND %s' % (google['cacheurl']))
            else:
                print("Google: NOT FOUND")
            # Yandex
            yandex = Yandex.cache(url)
            if yandex['success']:
                print('Yandex: FOUND %s' % yandex['cacheurl'])
            else:
                print("Yandex: NOT FOUND")
            # Archive.is
            try:
                arch = ArchiveIs.snapshots(url)
                if len(arch) > 0:
                    print('Archive.is: FOUND')
                    for s in arch:
                        print('-%s: %s' % (s['date'], s['archive']))
                else:
                    print('Archive.is: NOT FOUND')
            except requests.exceptions.ConnectTimeout:
                print('Archive.is: TIME OUT')
            # Web Archive
            web = ArchiveOrg.snapshots(url)
            if len(web) > 0:
                print('Archive.org: FOUND')
                for s in web:
                    print('-%s: %s' % (s['date'], s['archive']))
            else:
                print('Archive.org: NOT FOUND')
            # Bing
            bing = Bing.cache(url)
            if bing['success']:
                print('Bing: FOUND %s (%s)' % (
                    bing['cacheurl'],
                    bing['date']
                ))
            else:
                print("Bing: NOT FOUND")

        elif args.source == "google":
            data = Google.cache(url)
            if data['success']:
                if args.dump:
                    print(data['data'])
                else:
                    print('Cache found: %s (%s)' % (
                            data['cacheurl'],
                            data['date']
                        )
                    )
            else:
                print('No Google cache for this url')
        elif args.source == "yandex":
            data = Yandex.cache(url)
            if data['success']:
                if args.dump:
                    print(data['data'])
                else:
                    print('Cache found: %s' % data['cacheurl'])
            else:
                print('Cache not found')
        elif args.source == "bing":
            data = Bing.cache(url)
            if data['success']:
                if args.dump:
                    print(data['data'])
                else:
                    print('Cache found: %s' % data['cacheurl'])
            else:
                print('Cache not found')
        elif args.source == 'archiveis':
            data = ArchiveIs.snapshots(url)
            if len(data) == 0:
                print('No snapshot found')
            else:
                if args.dump:
                    last = sorted(data, key=lambda x: x['date'], reverse=True)[0]
                    res = ArchiveIs.download_cache(last['archive'])
                    print(res['data'])
                else:
                    print('Snapshot founds:')
                    for s in data:
                        print('-%s: %s' % (s['date'], s['archive']))
        elif args.source == "webarchive":
            data = ArchiveOrg.snapshots(url)
            if len(data) > 0:
                if args.dump:
                    last = sorted(data, key=lambda x: x['date'], reverse=True)[0]
                    cache = ArchiveOrg.download_cache(data['archive'])
                    print(cache['data'])
                else:
                    print('Snapshots found:')
                    for s in data:
                        print('-%s: %s' % (s['date'], s['archive']))
            else:
                print("No snapshot found")
        else:
            self.parser.print_help()
