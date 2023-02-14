#! /usr/bin/env python

import json

from harpoon.commands.base import Command
from harpoon.lib.phishtank import Phishtank, PhishtankError


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
    config = {"Phishtank": []}

    def add_arguments(self, parser):
        parser.add_argument('URL', help='Phish URL')
        self.parser = parser

    def run(self, args, plugins):
        # May have a configuration
        print(self._config_data["VirusTotal"].get("toto", "aa"))
        if "Phishtank" in self._config_data:
            pt = Phishtank(self._config_data["Phishtank"].get("key", None))
        try:
            pt = Phishtank()
            res = pt.query(args.URL)
            print(json.dumps(res, indent=4))
        except PhishtankError:
            print("Requet failed")
