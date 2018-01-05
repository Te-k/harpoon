#! /usr/bin/env python
import sys
import json
from fullcontact import FullContact
from harpoon.commands.base import Command

class CommandFullContact(Command):
    """
    # FullContact

    **Request fullcontact.com API**

    * Search for a Twitter account: `harpoon fullcontact -t @tenacioustek`
    * Search for an email address: `harpoon fullcontact -e admin@example.org`
    * Search for a domain: `harpoon fullcontact -d github.com`
    """
    name = "fullcontact"
    description = "Requests Full Contact API (https://www.fullcontact.com/)"
    config = {'FullContact': ['key']}

    def add_arguments(self, parser):
        parser.add_argument('--twitter', '-t', help='Search person based on twitter')
        parser.add_argument('--email', '-e', help='Search person based on email')
        parser.add_argument('--md5', '-m', help='Search person based on md5 of email')
        parser.add_argument('--phone', '-p', help='Search person based on phone number')
        parser.add_argument('--domain', '-d', help='Search company based on domain')
        self.parser = parser

    def run(self, conf, args, plugins):
        fc = FullContact(conf['FullContact']['key'])
        if args.twitter:
            res = fc.person(twitter=args.twitter)
            print(json.dumps(res.json(), sort_keys=True, indent=4))
        elif args.email:
            res = fc.person(email=args.email)
            print(json.dumps(res.json(), sort_keys=True, indent=4))
        elif args.phone:
            res = fc.person(phone=args.phone)
            print(json.dumps(res.json(), sort_keys=True, indent=4))
        elif args.md5:
            res = fc.person(emailMD5=args.md5)
            print(json.dumps(res.json(), sort_keys=True, indent=4))
        elif args.domain:
            res = fc.person(domain=args.domain)
            print(json.dumps(res.json(), sort_keys=True, indent=4))
        else:
            self.parser.print_help()

