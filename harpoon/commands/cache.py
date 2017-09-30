#! /usr/bin/env python
import sys
from harpoon.commands.base import Command
from harpoon.lib.google import Google
from harpoon.lib.yandex import Yandex
from harpoon.lib.archiveis import ArchiveIs
from harpoon.lib.archiveorg import ArchiveOrg


class CommandCache(Command):
    name = "cache"
    description = "Request cache of different sources"

    def add_arguments(self, parser):
        parser.add_argument('URL', help='URL of the cache')
        parser.add_argument(
            '--source', '-s',
            choices=['all', 'google', 'yandex', 'webarchive', 'archiveis'],
            default='all',
            help='Source of the cache'
        )
        parser.add_argument('--dump', '-D', action='store_true', help='Dump data')

    def run(self, conf, args):
        if args.source == 'all':
            if args.dump:
                print("Please specify the source to dump the data")
                sys.exit(1)
            # Google
            google = Google.cache(args.URL)
            if google['success']:
                print('Google: FOUND %s (%s)' % (
                    google['url'],
                    google['date']
                ))
            else:
                print("Google: NOT FOUND")
            # Yandex
            yandex = Yandex.cache(args.URL)
            if yandex['success']:
                print('Yandex: FOUND %s' % yandex['url'])
            else:
                print("Yandex: NOT FOUND")
            # Archive.is
            arch = ArchiveIs.snapshots(args.URL)
            if len(arch) > 0:
                print('Archive.is: FOUND')
                for s in arch:
                    print('-%s: %s' % (s['date'], s['archive']))
            else:
                print('Archive.is: NOT FOUND')
            # Web Archive
            web = ArchiveOrg.snapshots(args.URL)
            if len(web) > 0:
                print('Archive.org: FOUND')
                for s in web:
                    print('-%s: %s' % (s['date'], s['archive']))
            else:
                print('Archive.org: NOT FOUND')

        elif args.source == "google":
            data = Google.cache(args.URL)
            if data['success']:
                if args.dump:
                    print(data['data'])
                else:
                    print('Cache found: %s (%s)' % (
                            data['url'],
                            data['date']
                        )
                    )
            else:
                print('No Google cache for this url')
        elif args.source == "yandex":
            data = Yandex.cache(args.URL)
            if data['success']:
                if args.dump:
                    print(data['data'])
                else:
                    print('Cache found: %s' % data['url'])
            else:
                print('Cache not found')
        elif args.source == 'archiveis':
            data = ArchiveIs.snapshots(args.URL)
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
            data = ArchiveOrg.snapshots(args.URL)
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
            pass
