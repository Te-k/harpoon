#! /usr/bin/env python
from harpoon.version import HARPOON_VERSION

from .base import HarpoonPlugin


class Version(HarpoonPlugin):
    """
    Show Harpoon version
    """

    name = "version"
    description = "Show Harpoon version"

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)

    def fetch(self):
        self.results = {"version": HARPOON_VERSION}

    def display_txt(self):
        print("Current Harpoon version is {}".format(self.results["version"]))
