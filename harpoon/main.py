import os
import sys
import argparse
import configparser
from harpoon.commands.base import Command

def load_config():
        config = configparser.ConfigParser()
        if os.path.isfile(os.path.join(os.path.expanduser("~"), ".harpoon")):
            config.read(os.path.join(os.path.expanduser("~"), ".harpoon"))
        return config

def init_plugins():
    plugin_dir = os.path.dirname(os.path.realpath(__file__)) + '/commands'
    plugin_files = [x[:-3] for x in os.listdir(plugin_dir) if x.endswith(".py")]
    sys.path.insert(0, plugin_dir)
    for plugin in plugin_files:
        mod = __import__(plugin)

    PLUGINS = {}
    for plugin in Command.__subclasses__():
        PLUGINS[plugin.name] = plugin()
    return PLUGINS


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='Commands')

    plugins = init_plugins()
    for p in plugins:
        sp = subparsers.add_parser(
            plugins[p].name,
            help=plugins[p].description
        )
        plugins[p].add_arguments(sp)
        sp.set_defaults(command=p)

    args = parser.parse_args()
    config = load_config()
    #print(args)
    if hasattr(args, 'command'):
        plugins[args.command].run(config, args)
    else:
        parser.print_help()
