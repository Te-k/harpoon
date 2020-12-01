#! /usr/bin/env python
import datetime
import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib
import urllib.request
import logging
import geoip2.database
import pyasn
import pytz
import requests
from dateutil.parser import parse
from greynoise import GreyNoise
from harpoon.commands.asn import CommandAsn
from harpoon.commands.base import Command
from harpoon.commands.tor import CommandTor
from harpoon.lib.robtex import Robtex, RobtexError
from harpoon.lib.urlhaus import UrlHaus, UrlHausError
from harpoon.lib.utils import bracket, is_ip, unbracket
from harpoon.lib.threatcrowd import ThreatCrowd, ThreatCrowdError
from IPy import IP
from OTXv2 import IndicatorTypes, OTXv2
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.enrichment import EnrichmentRequest
from pybinaryedge import BinaryEdge, BinaryEdgeException, BinaryEdgeNotFound
from pymisp import ExpandedPyMISP
from pythreatgrid2 import ThreatGrid, ThreatGridError
from threatminer import ThreatMiner
from virus_total_apis import PrivateApi, PublicApi


class CommandIp(Command):
    """
        # IP

        **Gathers information on an IP address**

        Get information on an IP:
        ```
    harpoon ip 172.34.127.2
    MaxMind: Located in None, United States
    MaxMind: ASN21928, T-Mobile USA, Inc.
    ASN 21928 - T-MOBILE-AS21928 - T-Mobile USA, Inc., US (range 172.32.0.0/11)

    Censys:     https://censys.io/ipv4/172.34.127.2
    Shodan:     https://www.shodan.io/host/172.34.127.2
    IP Info:    http://ipinfo.io/172.34.127.2
    BGP HE:     https://bgp.he.net/ip/172.34.127.2
    IP Location:    https://www.iplocation.net/?query=172.34.127.2
        ```
    """

    name = "ip"
    description = "Gather information on an IP address"
    config = None
    update_needed = True
    geocity = "/usr/share/GeoIP/GeoLite2-City.mmdb"
    geoasn = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
    asnname = os.path.join(os.path.expanduser("~"), ".config/harpoon/asnnames.csv")
    asncidr = os.path.join(os.path.expanduser("~"), ".config/harpoon/asncidr.dat")
    specific_ips = os.path.join(os.path.expanduser("~"), ".config/harpoon/iplist.csv")

    def add_arguments(self, parser):
        parser.add_argument("IP", help="IP address")
        self.parser = parser

    def update(self):
        file_name, headers = urllib.request.urlretrieve(
            "http://www.cidr-report.org/as2.0/autnums.html"
        )
        fin = open(file_name, "r", encoding="latin-1", errors="ignore")
        fout = open(self.asnname, "w+")
        line = fin.readline()
        reg = re.compile(
            '^<a href="/cgi-bin/as-report\?as=AS\d+&view=2.0">AS(\d+)\s*</a> (.+)$'
        )
        while line != "":
            res = reg.match(line)
            if res:
                fout.write("%s|%s\n" % (res.group(1), res.group(2)))
            line = fin.readline()
        fin.close()
        fout.close()
        print("-asnname.csv")
        print("Downloading CIDR data")
        try:
            os.remove(self.asncidr)
        except OSError:
            pass
        os.chdir("/tmp")
        subprocess.call(["pyasn_util_download.py", "--latest"])
        ls = glob.glob("rib*.bz2")[0]
        subprocess.call(["pyasn_util_convert.py", "--single", ls, "latest.dat"])
        shutil.move("latest.dat", self.asncidr)
        print("-asncidr.dat")

    def ip_get_asn(self, ip):
        """
        Take an IP address and returns the asn number and name
        returns {'asn': 1234, 'name': 'FORTUM-AS Fortum, FI'}
        If not found, returns {'asn': 0, 'name': ''}
        """
        self.check_geoipdb()
        try:
            asndb = geoip2.database.Reader(self.geoasn)
            res = asndb.asn(ip)
            asn = res.autonomous_system_number
            asn_name = res.autonomous_system_organization
        except geoip2.errors.AddressNotFoundError:
            # TODO: check in the other ASN db
            return {"asn": 0, "name": ""}
        return {"asn": asn, "name": asn_name}

    def check_geoipdb(self):
        """
        Check if the GeoIP database is present on the system
        Depending on geoipupdate version it can be stored in:
        /usr/share/GeoIP/
        /var/lib/GeoIP
        /usr/local/var/GeoIP/
        """
        if os.path.isfile("/usr/share/GeoIP/GeoLite2-City.mmdb"):
            self.geocity = "/usr/share/GeoIP/GeoLite2-City.mmdb"
        elif os.path.isfile("/var/lib/GeoIP/GeoLite2-City.mmdb"):
            self.geocity = "/var/lib/GeoIP/GeoLite2-City.mmdb"
        elif os.path.isfile("/usr/local/var/GeoIP/GeoLite2-City.mmdb"):
            self.geocity = "/usr/local/var/GeoIP/GeoLite2-City.mmdb"
        else:
            print("Impossible to find GeoIP db")
            print("Make sure you have geoipupdate correctly configured")
            sys.exit(1)

        if os.path.isfile("/usr/share/GeoIP/GeoLite2-ASN.mmdb"):
            self.geoasn = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
        elif os.path.isfile("/var/lib/GeoIP/GeoLite2-ASN.mmdb"):
            self.geoasn = "/var/lib/GeoIP/GeoLite2-ASN.mmdb"
        elif os.path.isfile("/usr/local/var/GeoIP/GeoLite2-ASN.mmdb"):
            self.geoasn = "/usr/local/var/GeoIP/GeoLite2-ASN.mmdb"
        else:
            print("Impossible to find GeoIP ASN db")
            print("Make sure you have geoipupdate correctly configured")
            print("It should include this configuration")
            print("EditionIDs GeoLite2-Country GeoLite2-City GeoLite2-ASN")
            sys.exit(1)

    def ipinfo(self, ip, dns=True):
        """
        Return information on an IP address
        {"asn", "asn_name", "city", "country"}
        """
        self.check_geoipdb()
        ipinfo = {}
        if dns:
            ipinfo["hostname"] = ""
            try:
                ipinfo["hostname"] = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                pass
        try:
            citydb = geoip2.database.Reader(self.geocity)
            res = citydb.city(ip)
            ipinfo["city"] = res.city.name
            ipinfo["country"] = res.country.name
        except geoip2.errors.AddressNotFoundError:
            ipinfo["city"] = "Unknown"
            ipinfo["country"] = "Unknown"
        except FileNotFoundError:
            print(
                "GeoIP database not found, make sure you have correctly installed geoipupdate"
            )
            sys.exit(1)

        asninfo = self.ip_get_asn(ip)
        ipinfo["asn"] = asninfo["asn"]
        ipinfo["asn_name"] = asninfo["name"]
        ipinfo["specific"] = ""
        try:
            with open(self.specific_ips) as f:
                data = f.read().split("\n")
            for d in data:
                if d.strip().startswith(ip):
                    ipinfo["specific"] = d.split(",")[1].strip()
        except FileNotFoundError:
            pass
            # TODO: add private
        asnc = CommandAsn()
        res = asnc.asn_caida(ipinfo["asn"])
        ipinfo["asn_type"] = res["type"]
        return ipinfo

    def run(self, conf, args, plugins):
        ip = unbracket(args.IP)
        if not is_ip(ip):
            print("Invalid IP address")
            sys.exit(1)
        # FIXME: move code here in a library
        ipinfo = self.ipinfo(ip)
        print(
            "MaxMind: Located in %s, %s" % (ipinfo["city"], ipinfo["country"])
        )
        if ipinfo["asn"] == 0:
            print("MaxMind: IP not found in the ASN database")
        else:
            print("MaxMind: ASN%i, %s" % (ipinfo["asn"], ipinfo["asn_name"]))
            print("CAIDA Type: %s" % ipinfo["asn_type"])
        try:
            asndb2 = pyasn.pyasn(self.asncidr)
            res = asndb2.lookup(ip)
        except OSError:
            print("Configuration files are not available")
            print("Please run harpoon update before using harpoon")
            sys.exit(1)
        if res[1] is None:
            print("IP not found in ASN database")
        else:
            # Search for name
            f = open(self.asnname, "r")
            found = False
            line = f.readline()
            name = ""
            while not found and line != "":
                s = line.split("|")
                if s[0] == str(res[0]):
                    name = s[1].strip()
                    found = True
                line = f.readline()

            print("ASN %i - %s (range %s)" % (res[0], name, res[1]))
        if ipinfo["hostname"] != "":
            print("Hostname: %s" % ipinfo["hostname"])
        if ipinfo["specific"] != "":
            print("Specific: %s" % ipinfo["specific"])
        ipy = IP(ip)
        if ipy.iptype() == "PRIVATE":
            "Private IP"
        print("")
        if ipy.version() == 4:
            print("Censys:\t\thttps://censys.io/ipv4/%s" % ip)
            print("Shodan:\t\thttps://www.shodan.io/host/%s" % ip)
            print("IP Info:\thttp://ipinfo.io/%s" % ip)
            print("BGP HE:\t\thttps://bgp.he.net/ip/%s" % ip)
            print("IP Location:\thttps://www.iplocation.net/?query=%s" % ip)
