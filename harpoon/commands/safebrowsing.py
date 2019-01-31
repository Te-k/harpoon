#! /usr/bin/env python
import sys
from harpoon.commands.base import Command
from pysafebrowsing import SafeBrowsing

class CommandSafeBrowsing(Command):
    """
    # Google Safe Browsing

    **Check online Safe Browsing information**

    * Query an url: `harpoon safebrowsing url URL`
    * Query a list of domains or url from a file with CSV output: `harpoon safebrowsing file FILE -f csv`
    """
    name = "safebrowsing"
    description = "Check if the given domain is in Google safe Browsing list"
    config = {'SafeBrowsing': ['key']}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='SubCommands')
        parser_b = subparsers.add_parser('url', help='Query an URL')
        parser_b.add_argument('URL', help='URL to be requested')
        parser_b.add_argument('--json', '-j', action='store_true', help='Show raw json')
        parser_b.set_defaults(subcommand='url')
        parser_c = subparsers.add_parser('file', help='Check domains or urls from a file')
        parser_c.add_argument('FILE', help='File path')
        parser_c.add_argument('--format', '-f', help='Output format',
            choices=["json", "csv", "txt"], default="txt")
        parser_c.set_defaults(subcommand='file')
        self.parser = parser

    def run(self, conf, args, plugins):
        sb = SafeBrowsing(conf['SafeBrowsing']['key'])
        if 'subcommand' in args:
            if args.subcommand == 'url':
                try:
                    if args.URL.startswith("http"):
                        res = sb.lookup_url(args.URL)
                    else:
                        res = sb.lookup_url("http://" + args.URL + "/")
                except SafeBrowsingInvalidApiKey:
                    print("Invalid API key!")
                    sys.exit(1)
                except SafeBrowsingWeirdError:
                    print("Weird Error!")
                    sys.exit(1)
                else:
                    if args.json:
                        print(json.dumps(res, sort_keys=True, indent=4))
                    else:
                        if res["malicious"]:
                            print("Malicious: Yes")
                            print("Platforms: %s" % ", ".join(res["platforms"]))
                            print("Threats: %s" % ", ".join(res["threats"]))
                        else:
                            print("Malicious: No")
            elif args.subcommand == 'file':
                with open(args.FILE, 'r') as f:
                    data = f.read()
                domains = [d.strip() for d in data.split()]
                res = sb.lookup_urls(domains)
                if args.format == "txt":
                    for domain in res:
                        if res[domain]["malicious"]:
                            print("%s\tMalicious" % domain)
                        else:
                            print("%s\tOk" % domain)
                elif args.format == "json":
                    print(json.dumps(res, sort_keys=True, indent=4))
                else:
                    print("Url|Malicious|Threat|Platform")
                    for domain in res:
                        if res[domain]["malicious"]:
                            print("%s|%s|%s|%s" % (
                                    domain,
                                    "Yes",
                                    ",".join(res[domain]["threats"]),
                                    ",".join(res[domain]["platforms"])
                                )
                            )
                        else:
                            print("%s|No||" % domain)
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
