#! /usr/bin/env python
import shodan

from .base import HarpoonPlugin


class Shodan(HarpoonPlugin):
    """
    # Shodan

    **Get information on an IP address from Shodan (https://www.shodan.io/)**

    * `harpoon shodan IP`
    """

    name = "shodan"
    description = "Get information on an IP address from Shodan"
    config_structure = ["key"]

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.add_argument("IP", help="IP address")

    def fetch(self):
        ip = self.unbracket(self.args.IP)
        if not self.is_ip(ip):
            print("Invalid IP address")
            return

        api = shodan.Shodan(self.config["key"])
        try:
            self.results = api.host(ip)
        except shodan.exception.APIError as e:
            print("Error: {}".format(e))
            self.results = None

    def display_txt(self):
        if self.results is None:
            print("IP not found in Shodan")
            return

        for d in self.results["data"]:
            print(d["timestamp"])
            print(d["_shodan"]["module"])
            print("{}/{}".format(d["transport"], d["port"]))
            print(d["data"])
            print("")
