#! /usr/bin/env python
import sys
import os
import subprocess
from shutil import copyfile
from harpoon.commands.base import Command


class CommandConfig(Command):
    """
    # Configuration command

    **Help managing Harpoon configuration**

    * Create and update configuration file: `harpoon config`
    * Test plugins' configuration: `harpoon config -c`
    * Download or update databases: `harpoon config -u`

    Configuration file is stored in `~/.harpoon/config`
    """
    name = "config"
    description = "Configure Harpoon"

    def add_arguments(self, parser):
        parser.add_argument('--show', '-s', action='store_true',
            help='Show harpoon configuration')
        parser.add_argument('--check', '-c', action='store_true',
            help='Config harpoon configuration')

    def run(self, conf, args, plugins):
        configdir = os.path.join(os.path.expanduser('~'), '.config/harpoon')
        configpath = os.path.join(os.path.expanduser('~'), '.config/harpoon/config')
        if args.show:
            if not os.path.isfile(configpath):
                print('Config file does not exist, use harpoon config to create it')
                sys.exit(1)
            else:
                with open(configpath, 'r') as f:
                    print(f.read())
        elif args.check:
            print('Configuration check:')
            for p in plugins:
                if plugins[p].config_needed:
                    if plugins[p].test_config(conf):
                        if len(p) < 7:
                            print('-%s\t\t -> OK' % p)
                        else:
                            print('-%s\t -> OK' % p)
                    else:
                        if len(p) < 7:
                            print('-%s\t\t -> FAILED' % p)
                        else:
                            print('-%s\t -> FAILED' % p)
                else:
                    if len(p) < 7:
                        print('-%s\t\t -> OK' % p)
                    else:
                        print('-%s\t -> OK' % p)
        else:
            if not os.path.isdir(configdir):
                os.makedirs(configdir)
            if not os.path.isfile(configpath):
                origpath = os.path.join(
                    os.path.realpath(__file__)[:-18],
                    'data/example.conf'
                )
                copyfile(origpath, configpath)
            subprocess.call(os.environ.get('EDITOR', 'vi') + ' ' + configpath, shell=True)
