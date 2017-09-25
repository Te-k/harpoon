#! /usr/bin/env python
from harpoon.commands.base import Command
from harpoon.lib.bitly import Bitly

class CommandBitly(Command):
    name = "bitly"

    def run(self):
        print('Bitly')

    def add_arguments(self, parser):
        parser.add_argument('--hash', '-H', help='HASH of a link')
        parser.add_argument('--file', '-f', help='File containing list of hashes')
