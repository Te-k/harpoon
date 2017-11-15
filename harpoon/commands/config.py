#! /usr/bin/env python
import sys
import os
import subprocess
from shutil import copyfile
from harpoon.commands.base import Command


class CommandConfig(Command):
    """
    Configuration commange : help creating harpoon conf
    """
    name = "config"
    description = "Configure Harpoon"

    def add_arguments(self, parser):
        parser.add_argument(
            '--show',
            '-s',
            action='store_true',
            help='Show harpoon configuration'
        )

    def run(self, conf, args):
        configpath = os.path.join(os.path.expanduser('~'), '.harpoon')
        if args.show:
            if not os.path.isfile(configpath):
                print('Config file does not exist, use harpoon config to create it')
                sys.exit(1)
            else:
                with open(configpath, 'r') as f:
                    print(f.read())
        else:
            if not os.path.isfile(configpath):
                origpath = os.path.join(
                    os.path.realpath(__file__)[:-18],
                    'data/example.conf'
                )
                copyfile(origpath, configpath)
            subprocess.call(os.environ.get('EDITOR', 'vi') + ' ' + configpath, shell=True)
