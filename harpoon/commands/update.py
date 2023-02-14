#! /usr/bin/env python
import os
import subprocess

from harpoon.commands.base import Command


class CommandUpdate(Command):
    """
    # Update command

    **Update information used by Harpoon**

    * `harpoon update`

    Downloads several files in harpoon config folder (.config/harpoon)
    """
    name = "update"
    description = "Update Harpoon data"

    def add_arguments(self, parser):
        pass

    def run(self, args, plugins):
        configdir = os.path.join(os.path.expanduser('~'), '.config/harpoon')
        if not os.path.isdir(configdir):
            os.makedirs(configdir)
        print("Updating all plugins data:")
        for p in plugins:
            if plugins[p].update_needed:
                print("Updating plugin %s" % p)
                plugins[p].update()
        print("Updating GeoIP database")
        print("sudo geoipupdate")
        a = subprocess.run(['sudo', 'geoipupdate'])
        if a.returncode != 0:
            print("Impossible to launch geoipupdate")
            print("Please make sure you have the package installed and correctly configured")
            print("See https://github.com/Te-k/harpoon/wiki/Installation")
