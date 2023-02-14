#! /usr/bin/env python
import requests
from pypermacc import Permacc, PermaccError

from harpoon.commands.base import Command
from harpoon.lib.archiveis import ArchiveIs
from harpoon.lib.archiveorg import ArchiveOrg
from harpoon.lib.utils import unbracket


class CommandSave(Command):
    """
    # Save plugin

    **Save an URL in cache platforms (archive.is, archive.org, perma.cc)**

    Commands:
    * Save an url: `harpoon save URL`
    """
    name = "save"
    description = "Save a webpage in cache platforms"
    config = {}

    def add_arguments(self, parser):
        parser.add_argument('URL', help='URL to save')
        self.parser = parser

    def run(self, args, plugins):
        print("Saving in cache platforms:")
        # Archive.is
        try:
            ai_url = ArchiveIs.capture(unbracket(args.URL))
        except requests.exceptions.TooManyRedirects:
            print("Impossible to save in Archive.is")
        else:
            print("Archive.is: %s" % ai_url)

        # Web Archive
        try:
            ao_url = ArchiveOrg.capture(unbracket(args.URL))
        except KeyError:
            print("Impossible to save in Web Archive")
        else:
            print("Web Archive: %s" % ao_url)

        # Perma.cc
        if 'Permacc' in self._config_data and 'key' in self._config_data['Permacc']:
            pc = Permacc(self._config_data['Permacc']['key'])
            try:
                saved = pc.archive_create(unbracket(args.URL))
            except PermaccError:
                print("Impossible to save in Permacc")
            else:
                print("Permacc: https://perma.cc/%s" % saved["guid"])
