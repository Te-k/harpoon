#! /usr/bin/env python
import json

import phonenumbers
import requests

from harpoon.commands.base import Command


class CommandNumVerify(Command):
    """
    # Numverify.com plugin

    **Query NumVerify API**

    * Check a phone number
    """
    name = "numverify"
    description = "Query phone number information from NumVerify"
    config = {'NumVerify': ['key']}

    def query(self, phone, cc, key):
        params = {
                "access_key": key,
                "number": phone,
                "country_code": cc,
                "format": 1
        }
        r = requests.get("http://apilayer.net/api/validate", params=params)
        return r.json()

    def add_arguments(self, parser):
        parser.add_argument('PHONE',  help='Phone number')
        parser.add_argument('COUNTRY',  help='Country code (two letters)')
        self.parser = parser

    def run(self, args, plugins):
        x = phonenumbers.parse(args.PHONE, args.COUNTRY)
        print("Requesting phone +{} - {} ({})".format(
            x.country_code,
            x.national_number,
            args.COUNTRY
        ))
        res = self.query(
            x.national_number,
            args.COUNTRY,
            self._config_data['NumVerify']['key'])
        print(json.dumps(res, sort_keys=False, indent=4))
