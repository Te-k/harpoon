import argparse
import configparser
import os

import appdirs

from harpoon.plugins import PLUGINS


def load_config():
    config_path = os.path.join(appdirs.user_config_dir("harpoon"), "config")
    config = configparser.ConfigParser()
    if os.path.isfile(config_path):
        config.read(config_path)
    return config


# Main
# ==============================================================================
def cli():
    config = load_config()
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="Plugins")

    plugins = {}
    for plugin in sorted(PLUGINS, key=lambda x: x.__name__):
        sp = subparsers.add_parser(plugin.name, help=plugin.description)
        plugin_o = plugin(config, sp)
        sp.set_defaults(plugin=plugin_o.name)
        plugins[plugin_o.name] = plugin_o

    args = parser.parse_args()
    if hasattr(args, "plugin"):
        plugins[args.plugin].prerun(args, plugins)
        plugins[args.plugin].run()
    else:
        parser.print_help()
