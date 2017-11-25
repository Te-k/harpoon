#! /usr/bin/env python
import sys
import os
import json
import datetime
import urllib.request
import tarfile
import geoip2.database
from IPy import IP
from harpoon.commands.base import Command
from harpoon.lib.utils import bracket, unbracket

class CommandIp(Command):
    name = "ip"
    description = "Gather information on an IP address"
    config = None
    update_needed = True
    geocity = os.path.join(os.path.expanduser('~'), '.config/harpoon/GeoLite2-City.mmdb')
    geoasn = os.path.join(os.path.expanduser('~'), '.config/harpoon/GeoLite2-ASN.mmdb')

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('info', help='Information on an IP')
        parser_a.add_argument('IP', help='IP address')
        parser_a.set_defaults(subcommand='info')
        self.parser = parser

    def update(self):
        # Download Maxmind
        print("Downloading MaxMind GeoIP Database")
        try:
            os.remove(self.geocity)
        except OSError:
            pass
        try:
            os.remove(self.geoasn)
        except OSError:
            pass
        file_name, headers = urllib.request.urlretrieve('http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz')
        tar = tarfile.open(file_name, 'r')
        mmdb = tar.extractfile(tar.getmembers()[3])
        with open(self.geocity, 'wb+') as f:
            f.write(mmdb.read())
        mmdb.close()
        print("-GeoLite2-City.mmdb")
        file_name, headers = urllib.request.urlretrieve('http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz')
        tar = tarfile.open(file_name, 'r')
        mmdb = tar.extractfile(tar.getmembers()[3])
        with open(self.geoasn, 'wb+') as f:
            f.write(mmdb.read())
        mmdb.close()
        print("-GeoLite2-ASN.mmdb")

    def run(self, conf, args):
        if 'subcommand' in args:
            if args.subcommand == 'info':
                ip = unbracket(args.IP)
                try:
                    ipy = IP(ip)
                except ValueError:
                    print('Invalid IP format, quitting...')
                    return
                citydb = geoip2.database.Reader(self.geocity)
                asndb = geoip2.database.Reader(self.geoasn)
                res = citydb.city(ip)
                print('Located in %s, %s' % (
                        res.city.name,
                        res.country.name
                    )
                )
                res = asndb.asn(ip)
                print('ASN%i, %s' % (
                        res.autonomous_system_number,
                        res.autonomous_system_organization
                    )
                )
                if ipy.iptype() == "PRIVATE":
                    "Private IP"
                if ipy.version() == 4:
                    print("Censys: https://censys.io/ipv4/%s" % ip)
                    print("Shodan: https://www.shodan.io/host/%s" % ip)
                    print("IP Info: http://ipinfo.io/%s" % ip)

            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
