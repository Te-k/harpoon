#! /usr/bin/env python
import consolemd

from .base import HarpoonPlugin


class Help(HarpoonPlugin):
    """
    Show help on a Harpoon plugins
    """

    name = "help"
    description = "Show help on Harpoon plugins"

    def __init__(self, config, parser):
        super().__init__(config=config, parser=parser)
        self.add_argument(
            "COMMAND", help="Show the help of the given command", nargs="?"
        )

    def fetch(self):
        self.results = {}
        if self.args.COMMAND in self.plugins:
            self.results["help"] = "\n".join(
                [
                    item.strip()
                    for item in self.plugins[self.args.COMMAND].__doc__.splitlines()
                ]
            )

    def display_txt(self):
        if "help" in self.results:
            renderer = consolemd.Renderer()
            renderer.render(self.results["help"])
        else:
            print("Please provide a Harpoon command")
