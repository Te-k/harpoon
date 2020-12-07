#! /usr/bin/env python
import os
import json
import requests
from io import BytesIO
from zipfile import ZipFile
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket, is_ip


class CommandUmbrella(Command):
    """
    # Umbrella

    **Check if a domain is in Umbrella Top 1 million domains**

    * `harpoon umbrella domain DOMAIN`
    * Check a list of domains in a file : `harpoon umbrella list FILE`
    """
    name = "umbrella"
    description = "Check if a domain is in Umbrella Top 1 million domains"
    topfile = os.path.join(os.path.expanduser("~"), ".config/harpoon/umbrellatop1m.csv")

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('domain', help='Check a domain on Umbrella')
        parser_a.add_argument('DOMAIN',  help='DOMAIN to be queried')
        parser_a.set_defaults(subcommand='domain')
        parser_b = subparsers.add_parser('list', help='Check a list of domains')
        parser_b.add_argument('FILE',  help='File containing list of domains')
        parser_b.set_defaults(subcommand='list')

        self.parser = parser

    def update(self):
        """
        Download file http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
        """
        print("Downloading Umbrella Top 1 million websites")
        if os.path.isfile(self.topfile):
            os.remove(self.topfile)
        r = requests.get("http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip")
        if r.status_code != 200:
            print("Impossible to download Umbrella Top 1 millon CSV file.")
            return False
        input_zip=ZipFile(BytesIO(r.content))
        fname = input_zip.namelist()[0]
        with open(self.topfile, "a+") as f:
            f.write(input_zip.read(fname).decode('utf-8'))
        return True

    def check(self, domain):
        """
        Check if a domain is in the Umbrella Top 1 million list
        """
        if not os.path.isfile(self.topfile):
            print("Umbrella Top 1 million file not available, please do harpoon update")
            return None
        with open(self.topfile) as f:
            line = f.readline().strip()
            while line != '':
                l = line.split(',')
                if domain == l[1]:
                    return int(l[0])
                line = f.readline().strip()
        return None

    def run(self, conf, args, plugins):
        if 'subcommand' in args:
            if args.subcommand == 'domain':
                rank = self.check(unbracket(args.DOMAIN))
                if rank:
                    print("Found ranked {}".format(rank))
                else:
                    print("Not found")
            elif args.subcommand == 'list':
                umbrella = {}
                with open(self.topfile) as f:
                    for l in f.read().split('\n'):
                        if l.strip() == '':
                            continue
                        ll = l.strip().split(',')
                        umbrella[ll[1]] = ll[0]

                with open(args.FILE) as f:
                    data = f.read().split('\n')
                data.remove('')

                for d in data:
                    if d.strip() == "":
                        continue
                    if d.strip() in umbrella.keys():
                        print("{} in the umbrella list at {} position".format(
                            d.strip(),
                            umbrella[d.strip()]
                        ))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()

    def intel(self, type, query, data, conf):
        if type == "domain":
            rank = self.check(query)
            if rank:
                data["reports"].append({
                    "date": "",
                    "title": "Domain ranked as {} by Cisco Umbrella".format(rank),
                    "url": "",
                    "source": "Cisco Umbrella"
                })
