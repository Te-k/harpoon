import json
from typing import Any

from IPy import IP

from harpoon.utils import json_serial


class InvalidConfiguration(Exception):
    pass


class HarpoonPlugin:
    def __init__(self, config, parser):
        """
        Initialize the plugin before launching it
        """
        self._config = config
        self.parser = parser
        self.results: Any = None
        self.subcommands = None
        self.subparser = None
        if self.parser:
            self.parser.add_argument(
                "--json", "-j", action="store_true", help="JSON version of the results"
            )
        self.config_structure = None
        # Intel data structures
        self.passive_dns = []
        self.reports = []
        self.urls = []

    def add_argument(self, *args, **kwargs):
        self.parser.add_argument(*args, **kwargs)

    def add_subcommand(self, subcommand):
        """
        Adds a subcommand to the plugin
        """
        if self.subcommands is None:
            self.subcommands = {}
            self.subparser = self.parser.add_subparsers(help="Subcommand")

        # Create a subparser
        parser = self.subparser.add_parser(subcommand.name, help=subcommand.description)
        subcommand_o = subcommand(self.config, parser)
        self.subcommands[subcommand.name] = subcommand_o
        parser.set_defaults(subcommand=subcommand.name)

    def prerun(self, args, plugins):
        """
        Provides all the data to run the plugin
        """
        self.args = args
        self.plugins = plugins

    def run(self):
        if not self.is_config_valid():
            raise InvalidConfiguration()
        self.fetch()
        self.display()

    def fetch(self) -> None:
        if self.subcommands is not None:
            if "subcommand" in self.args:
                if self.args.subcommand in self.subcommands:
                    self.subcommands[self.args.subcommand].prerun(
                        self.args, self.plugins
                    )
                    self.subcommands[self.args.subcommand].fetch()
                    self.results = self.subcommands[self.args.subcommand].results
                else:
                    self.parser.print_help()
            else:
                self.parser.print_help()
        else:
            raise NotImplementedError

    def display(self):
        """
        Show the results
        """
        # Check if a subcommand is called
        if self.subcommands is not None:
            if "subcommand" in self.args:
                if self.args.subcommand in self.subcommands:
                    # A subcommand is called
                    self.subcommands[self.args.subcommand].display()
                    return

        # Otherwise display the results:
        if self.results is None:
            return
        if self.args.json:
            self.display_json()
        else:
            try:
                self.display_txt()
            except NotImplementedError:
                self.display_json()

    def display_json(self):
        """
        Display data in JSON
        """
        if self.results:
            print(json.dumps(self.results, indent=4, default=json_serial))
        else:
            print("No results have been acquired")

    def display_txt(self):
        raise NotImplementedError

    # -------------------------- Configuration ---------------------------------
    @property
    def config(self):
        if self._config is None:
            return {}
        if self.__class__.__name__ not in self._config:
            return {}
        return self._config[self.__class__.__name__]

    def is_config_valid(self) -> bool:
        """
        Check if the module is missing configuration to work.

        :return: Boolean
        """
        if self.config_structure is None:
            return True

        if self.__class__.__name__ not in self._config:
            return False

        for entry in self.config_structure:
            if entry not in self.config:
                return False
            if self.config[entry].strip() == "":
                return False
        return True

    # -------------------------- Intelligence functions ------------------------
    def intel_ip(self, ip: str):
        """
        Collect intelligence on an IP address
        """
        raise NotImplementedError

    def intel_domain(self, domain: str):
        """
        Collect intelligence on a domain
        """
        raise NotImplementedError

    def is_intel_enabled(self) -> bool:
        """
        Check if the plugin has intelligence enabled in configuration
        :return: boolean
        """
        if self.config is None:
            return False

        return self.config.get("intel", False)

    # --------------------------- Support functions ----------------------------
    def unbracket(self, entry: str) -> str:
        """Remove protective bracket from a string"""
        return entry.replace("[.]", ".")

    def bracket(self, entry: str) -> str:
        """Add protective bracket to a domain"""
        last_dot = entry.rfind(".")
        return entry[:last_dot] + "[.]" + entry[last_dot + 1 :]

    def is_ip(self, target: str) -> bool:
        """
        Test if a string is an IP address
        """
        if isinstance(target, str):
            try:
                IP(target)
                return True
            except ValueError:
                return False
        else:
            return False
