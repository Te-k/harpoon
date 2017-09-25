import os
import sys
import argparse
from harpoon.commands.base import Command

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
        sp = subparsers.add_parser(plugins[p].name, help='...')
        plugins[p].add_arguments(sp)
        sp.set_defaults(command=p)

    args = parser.parse_args()
    print(args)

    print(plugins)
