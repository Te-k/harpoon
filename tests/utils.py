import argparse
import configparser
import os

import pytest


def get_test_config():
    """
    Returns the configuration from the test configuration file
    """
    config = configparser.ConfigParser()
    fpath = os.path.join(os.path.dirname(__file__), "tests.conf")
    if os.path.isfile(fpath):
        config.read(fpath)
    return config


def launch_plugin(plugin, args, plugins={}):
    """
    Launches a plugin with the given arguments
    """
    config = get_test_config()

    # Generate the command parser
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(help="Plugins")
    sp = subparser.add_parser(plugin.name, help=plugin.description)
    pl = plugin(config, sp)
    sp.set_defaults(plugin=pl.name)

    vargs = parser.parse_args(args)

    # Run
    if pl.is_config_valid():
        pl.prerun(vargs, plugins)
        pl.run()
    else:
        pytest.skip("Configuration not set")
