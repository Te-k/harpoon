#! /usr/bin/env python
from harpoon.commands.base import Command
from harpoon.lib.utils import unbracket
from harpoon.lib.archiveis import ArchiveIs
from harpoon.lib.archiveorg import ArchiveOrg
from pypermacc import Permacc, PermaccError


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

    def run(self, conf, args, plugins):
        print("Saving in cache platforms:")
        # Archive.is
        try:
            ai_url = ArchiveIs.capture(unbracket(args.URL))
        except:
            print("Impossible to save in archive.is, weird")
        else:
            print("Archive.is: %s" % ai_url)

        # Web Archive
        try:
            ao_url = ArchiveOrg.capture(unbracket(args.URL))
        except:
            print("Impossible to save in web archive, weird.")
        else:
            print("Web Archive: %s" % ao_url)

        # Perma.cc
        if 'Permacc' in conf and 'key' in conf['Permacc']:
            pc = Permacc(conf['Permacc']['key'])
            try:
                saved = pc.archive_create(unbracket(args.URL))
            except PermaccError:
                print("Impossible to save in Permacc")
            else:
                print("Permacc: https://perma.cc/%s" % saved["guid"])
