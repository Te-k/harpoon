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
    pl = plugin(config)

    # Generate the command parser
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(help='Commands')
    sp = subparser.add_parser(
        pl.name,
    )
    pl.add_arguments(sp)
    sp.set_defaults(command=pl.name)

    vargs = parser.parse_args(args)

    # Run
    if pl.test_config():
        pl.run(vargs, plugins)
    else:
        pytest.skip("Configuration not set")
