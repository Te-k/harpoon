#! /usr/bin/env python
import sys
import os
import io
import consolemd
from harpoon.commands.base import Command


class CommandHelp(Command):
    """
    # Help Command

    **Show help for a command**
    Example : `harpoon help config`
    """
    name = "help"
    description = "Give help on an Harpoon command"

    def add_arguments(self, parser):
        parser.add_argument('COMMAND', help='Show the help of the given command', nargs='?')

    def run(self, conf, args, plugins, parser):
        if args.COMMAND in plugins:
            renderer = consolemd.Renderer()
            # Remove empty space at the beginning of lines
            content = [item.strip() for item in plugins[args.COMMAND].__doc__.splitlines()]
            renderer.render('\n'.join(content))
        else:
            parser.print_help()
