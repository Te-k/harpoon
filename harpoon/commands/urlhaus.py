#! /usr/bin/env python3

from harpoon.commands.base import Command
from harpoon.lib.urlhaus import UrlHaus, UrlHausError


class CommandUrlhaus(Command):
    """
    # URLhaus.ch

    * Submit a potential malicious URL: `harpoon urlhaus url URL`
    """

    name = "urlhaus"
    description = "Request urlhaus.abuse.ch API"
    config = {"UrlHaus": ["key"]}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help="Subcommand")
        parser_a = subparsers.add_parser("get-url", help="Request info on a URL")
        parser_a.add_argument("url", help="url")
        parser_a.set_defaults(subcommand="get-url")

        parser_b = subparsers.add_parser(
            "get-host",
            help="Request info on a host: IPv4 address, hostname or domain name",
        )
        parser_b.add_argument("host", help="host")
        parser_b.set_defaults(subcommand="get-host")

        parser_c = subparsers.add_parser(
            "get-payload", help="Request info about a payload: md5 or sha256"
        )
        parser_c.add_argument("payload", help="payload")
        parser_c.set_defaults(subcommand="get-payload")

        parser_d = subparsers.add_parser(
            "get-tag",
            help="Request info about a tag: Gozi, Trickbot...",
        )
        parser_d.add_argument("tag", help="tag")
        parser_d.set_defaults(subcommand="get-tag")

        parser_d = subparsers.add_parser(
            "get-signature", help="Request info about a signature: Gozi, Trickbot"
        )
        parser_d.add_argument("signature", help="signature")
        parser_d.set_defaults(subcommand="get-signature")

        parser_e = subparsers.add_parser(
            "get-sample", help="Request a malware sample identified by a hash (sha256)"
        )
        parser_e.add_argument("hash", help="hash")
        parser_e.set_defaults(subcommand="get-sample")

        self.parser = parser

    def check_config(self):
        if self.config is not "":
            return True
        return False

    def run(self, conf, args, plugins):
        urlhaus = UrlHaus(conf["UrlHaus"]["key"])
        if "subcommand" in args:
            if args.subcommand == "get-url":
                urlhaus.get_url(args.url)
            elif args.subcommand == "get-host":
                urlhaus.get_host(args.host)
            elif args.subcommand == "get-payload":
                urlhaus.get_payload(args.payload)
            elif args.subcommand == "get-tag":
                urlhaus.get_tag(args.tag)
            elif args.subcommand == "get-signature":
                urlhaus.get_signature(args.signature)
            elif args.subcommand == "get-sample":
                urlhaus.get_sample(args.hash)
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
