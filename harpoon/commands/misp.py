#! /usr/bin/env python
import sys
import pytz
from urllib.parse import urljoin
from dateutil.parser import parse
from collections import Counter
from harpoon.commands.base import Command
from pymisp import ExpandedPyMISP


class CommandMisp(Command):
    """
    # MISP

    **Queries a MISP (http://www.misp-project.org/) server**

    * List events (maybe a long list): `harpoon misp -l`
    * Get information on an event: `harpoon misp -e 342`
    * Get all the domain IOCs from an event: `harpoon misp -e 42 -t domain`
    * Search for an attribute: `harpoon misp -a example.org`
    """
    name = "misp"
    description = "Get information from a MISP server through the API"
    config = { 'Misp': ['url', 'key']}

    def add_arguments(self, parser):
        parser.add_argument('--list', '-l', action='store_true', help='List events')
        parser.add_argument('--event', '-e',  help='Event infos', type=int)
        parser.add_argument('--attr', '-a',  help='Search for this attribute')
        parser.add_argument('--type', '-t',  help='Search for attributes of this type')
        parser.add_argument('--raw', '-r', help='Print raw information', action='store_true')
        parser.add_argument('--no-tls', '-n', help='Do not validate TLS certificate (bad bad bad)', action='store_true')
        self.parser = parser

    def run(self, conf, args, plugins):
        server = ExpandedPyMISP(conf['Misp']['url'], conf['Misp']['key'], not args.no_tls)
        if args.list:
            # List events
            events = server.events(pythonify=True)
            for event in sorted(events, key=lambda x:x.id):
                print("%i : %s" % (event.id, event.info))
        elif args.event is not None:
            event = server.get_event(args.event, pythonify=True)
            if args.attr is None and args.type is None:
                if args.raw:
                    for a in event.attributes:
                        print(a.value)
                else:
                    print("Event {} : {}".format(event.id, event.info))
                    print("Tags : {}".format(", ".join(map(lambda x:str(x.name), event.tags))))
                    print("{} Attributes including:".format(len(event.attributes)))
                    attrs = Counter(map(lambda x:x.type, event.attributes))
                    attrs_ids = Counter(map(lambda x:x.type, filter(lambda x:x.to_ids, event.attributes)))
                    for type in attrs:
                        print("- %i %s (%i for detection)" % (attrs[type], type, attrs_ids[type]))
            else:
                if args.type is not None:
                    # Display all attributes from this type
                    for attr in event.attributes:
                        if attr.type == args.type:
                            if args.raw:
                                print("%s" % attr.value)
                            else:
                                print("{:20}{:10}{:40}{}{}".format(attr.category, attr.type, attr.value, attr.comment, attr.to_ids))
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
        elif args.attr is not None:
            res = server.search('attributes', value=args.attr)
            if len(res['Attribute']) == 0:
                print("Search %s: no results" % args.attr)
            else:
                print("Search %s, result founds" % args.attr)
                for attr in res['Attribute']:
                    print('{} - {}'.format(attr['Event']['id'], attr['Event']['info']))
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        if type in ["domain", "ip", "hash"]:
            print("[+] Checking MISP...")
            server = ExpandedPyMISP(conf["Misp"]["url"], conf["Misp"]["key"])
            misp_results = server.search("events", value=query)
            for event in misp_results:
                data["reports"].append({
                    "date": parse(event['Event']['date']).astimezone(pytz.utc),
                    "title": event['Event']['info'],
                    "source": "MISP",
                    "url": urljoin(conf['Misp']['url'], "events/view/".format(event['Event']['id']))
                })


