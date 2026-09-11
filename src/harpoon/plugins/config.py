#! /usr/bin/env python
import os
import subprocess
import sys
from shutil import copyfile

import appdirs
from rich.console import Console
from rich.table import Table

from .base import HarpoonPlugin


class Config(HarpoonPlugin):
    """
    # Configuration command

    **Help managing Harpoon configuration**

    * Create and update configuration file: `harpoon config`
    * Test plugins' configuration: `harpoon config -c`

    Configuration file is stored in `~/.harpoon/config`
    """

    name = "config"
    description = "Configure Harpoon"

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.add_argument(
            "--show", "-s", action="store_true", help="Show harpoon configuration"
        )
        self.parser.add_argument(
            "--check", "-c", action="store_true", help="Config harpoon configuration"
        )
        self.config_dir = appdirs.user_config_dir("harpoon")
        self.config_file = os.path.join(self.config_dir, "config")

    def fetch(self):
        if self.args.show:
            if not os.path.isfile(self.config_file):
                print("Config file does not exist, use harpoon config to create it")
                sys.exit(1)
            else:
                with open(self.config_file, "r") as f:
                    print(f.read())
        elif self.args.check:
            table = Table(title="Configuration Check")
            table.add_column("Plugin")
            table.add_column("Result")
            for p in self.plugins:
                if self.plugins[p].is_config_valid:
                    table.add_row(p, "OK")
                else:
                    table.add_row(p, "FAILED")
            console = Console()
            console.print(table)
        else:
            if not os.path.isdir(self.config_dir):
                os.makedirs(self.config_dir)
            if not os.path.isfile(self.config_file):
                origpath = os.path.join(
                    os.path.realpath(__file__)[:-18], "data/example.conf"
                )
                copyfile(origpath, self.config_file)
            subprocess.call(
                os.environ.get("EDITOR", "vi") + " " + self.config_file, shell=True
            )
