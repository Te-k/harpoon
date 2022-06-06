#! /usr/bin/env python

import base64
import json

import requests
from harpoon.commands.base import Command


class CommandPhishtank(Command):
    """
    # Phishtank Command

    * Get information on a URL from Phishtank API

    Example:
    ```
    $ harpoon phishtank URL
    ```  
    """
    name = "phishtank"
    description = "Gather information on a URL"
    config = None 
    url = "https://checkurl.phishtank.com/checkurl/"
    headers = {
            "User-Agent": "Harpoon (https://github.com/Te-k/harpoon)",
            "Content-Type": "application/x-www-form-urlencoded"
            }

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('url', help='Information on a url')
        parser_a.add_argument('URL', help='Phish URL')
        parser_a.set_defaults(subcommand='url')

        self.parser = parser

    def pretty_print(self, result):

        print("# Phishtank result for:", result['results']['url'])
        print('------------------------------')
        if result['results']['in_database'] is True:
            print('Present in database:', result['results']['in_database'])
            print('URL to submission:', result['results']['phish_detail_page'])
            print('Verified:', result['results']['verified'])
        else:
            print('Not found in Phishtank database!')

    def run(self, conf, args, plugins):
        if not 'subcommand' in args:
                self.parser.print_help()
        else:
            app_key = conf['Phishtank']['key']
            if app_key.strip() != "":
                app_key = conf['Phishtank']['key']
            else:
                app_key = None
                
            # Phishtank requires base64 or urlencoded URLs
            post_data = {
                    "url": base64.b64encode(args.URL.encode("utf-8")),
                    "format": "json",
                    "app_key": app_key,
                    }
            r = requests.post(self.url, data=post_data,  headers=self.headers)
            self.pretty_print(r.json())


