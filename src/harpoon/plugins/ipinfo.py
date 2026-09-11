#! /usr/bin/env python
from .base import HarpoonPlugin


class IpInfo(HarpoonPlugin):
    """
    # IpInfo

    **Get geolocation and network information on an IP address from the
    local ip66.dev database**

    * `harpoon ipinfo IP`
    """

    name = "ipinfo"
    description = "Get information on an IP address from the local ip66.dev database"

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.add_argument("IP", help="IP Address")

    def fetch(self):
        ip = self.unbracket(self.args.IP)
        if not self.is_ip(ip):
            print("Invalid IP address")
            return
        self.results = self.ipinfo(ip)

    def display_txt(self):
        if "autonomous_system_number" in self.results:
            print("AS{} - {}".format(self.results["autonomous_system_number"], self.results["autonomous_system_organization"]))
        print("Country: {}".format(self.results["country"]["names"]["en"]))

