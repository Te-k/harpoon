#! /usr/bin/env python
import sys
from collections import Counter
from harpoon.commands.base import Command
from mispy import MispServer, MispEvent


class CommandMisp(Command):
    """
    # MISP

    **Queries a MISP (http://www.misp-project.org/) server**

    * List events (maybe a long list): `harpoon misp -l`
    * Get information on an event: `harpoon misp -e 342`
    * Search for an attribute: `harpoon misp -a example.org`
    * Search for a list of indicators in a file: `harpoon misp -s FILE`
    """
    name = "misp"
    description = "Get information from a MISP server through the API"
    config = { 'Misp': ['url', 'key']}

    def add_arguments(self, parser):
        parser.add_argument('--list', '-l', action='store_true', help='List events')
        parser.add_argument('--event', '-e',  help='Event infos', type=int)
        parser.add_argument('--search', '-s',  help='Search for indicators from a file')
        parser.add_argument('--attr', '-a',  help='Search for this attribute')
        parser.add_argument('--type', '-t',  help='Search for attributes of this type')
        parser.add_argument('--raw', '-r', help='Print raw information', action='store_true')
        parser.add_argument('--no-tls', '-n', help='Do not validate TLS certificate (bad bad bad)', action='store_true')
        self.parser = parser

    def run(self, conf, args, plugins):
        # FIXME: have this in conf
        if args.no_tls:
            server = MispServer(url=conf['Misp']['url'], apikey=conf['Misp']['key'], ssl_chain=False)
        else:
            server = MispServer(url=conf['Misp']['url'], apikey=conf['Misp']['key'])
        if args.list:
            # List events
            events = server.events.list(0)
            for event in sorted(events, key=lambda x:x.id):
                print("%i : %s" % (event.id, event.info))
        elif args.attr is not None:
            res = server.attributes.search(value=args.attr)
            if len(res) == 0:
                print("Search %s: no results" % args.attr)
            else:
                print("Search %s, result founds" % args.attr)
                for event in res:
                    print("[+] %i - %s" % (event.id, event.info))
                    for attr in event.attributes:
                        if args.type is not None:
                            if attr.type == args.type:
                                if args.attr.lower() in str(attr.value).lower() or \
                                        args.attr.lower() in str(attr.comment).lower():
                                    print("\t%s (%s / %s) %s" % (attr.value, attr.category, attr.type, attr.comment))
                        else:
                            if args.attr.lower() in str(attr.value).lower() or \
                                    args.attr.lower() in str(attr.comment).lower():
                                print("\t%s (%s / %s) %s" % (attr.value, attr.category, attr.type, attr.comment))


        elif args.event is not None:
            event = server.events.get(args.event)
            if args.attr is None and args.type is None:
                print("Event %i : %s" % (event.id, event.info))
                print("Tags : %s" % ", ".join(map(lambda x:str(x.name), event.tags)))
                print("%i Attributes including:" % len(event.attributes))
                attrs = Counter(map(lambda x:x.type, event.attributes))
                attrs_ids = Counter(map(lambda x:x.type, filter(lambda x:x.to_ids, event.attributes)))
                for type in attrs:
                    print("\t- %i %s (%i for detection)" % (attrs[type], type, attrs_ids[type]))
            else:
                if args.type is not None:
                    # Display all attributes from this type
                    for attr in event.attributes:
                        if attr.type == args.type:
                            if args.raw:
                                print("%s" % attr.value)
                            else:
                                print("%s\t%s\t%s\t%s\t%s" % (attr.category, attr.type, attr.value, attr.comment, attr.to_ids))
                elif args.attr is not None:
                    # search by attribute value
                    for attr in event.attributes:
                        if args.attr in str(attr.value):
                            print("%s\t%s\t%s\t%s\t%s" %
                                (
                                    attr.category,
                                    attr.type,
                                    attr.value,
                                    attr.comment,
                                    attr.to_ids
                                )
                            )
        elif args.search:
            with open(args.search, 'r') as infile:
                data = infile.read().split()
            for d in data:
                print("Searching for %s" % d.strip())
                res = server.attributes.search(value=d.strip())
                if len(res) == 0:
                    print("\tNo results")
                else:
                    for event in res:
                        print("\t[+] %i - %s" % (event.id, event.info))
                        for attr in event.attributes:
                            if d.strip().lower() in str(attr.value).lower() or \
                                d.strip().lower() in str(attr.comment).lower():
                                    print("\t\t%s (%s / %s) %s" % (attr.value, attr.category, attr.type, attr.comment))
        else:
            self.parser.print_help()
