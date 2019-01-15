import os
import sys
import argparse
import configparser
import signal
from harpoon.commands.base import Command


def handle_stop(sig, frame):
    print('Okay, Okay, I stop...')
    sys.exit(1)


def load_config():
    config = configparser.ConfigParser()
    if os.path.isfile(os.path.join(os.path.expanduser("~"), ".config/harpoon/config")):
        config.read(os.path.join(os.path.expanduser("~"), ".config/harpoon/config"))
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
    signal.signal(signal.SIGINT, handle_stop)

    # Init plugins
    plugins = init_plugins()
    for p in sorted(plugins.keys()):
        sp = subparsers.add_parser(
            plugins[p].name,
            help=plugins[p].description
        )
        plugins[p].add_arguments(sp)
        sp.set_defaults(command=p)

    args = parser.parse_args()
    config = load_config()
    if hasattr(args, 'command'):
        # Config plugin need plugin list
        if not plugins[args.command].test_config(config):
            print('Invalid configuration for this plugin, quitting...')
            sys.exit(1)
        else:
            # Ugly
            if args.command == "help":
                plugins[args.command].run(config, args, plugins, parser)
            else:
                plugins[args.command].run(config, args, plugins)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
