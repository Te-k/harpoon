import argparse
import configparser
import os
from datetime import datetime, timedelta

import appdirs
import requests

from harpoon.plugins import PLUGINS

IP66_MMDB_URL = "https://downloads.ip66.dev/db/ip66.mmdb"
IP66_MMDB_MAX_AGE = timedelta(days=30)


def load_config():
    config_path = os.path.join(appdirs.user_config_dir("harpoon"), "config")
    config = configparser.ConfigParser()
    if os.path.isfile(config_path):
        config.read(config_path)
    return config


def download_needed_files():
    """
    Download the files needed by Harpoon plugins into the config directory,
    refreshing any file that is more than a month old.
    """
    config_dir = appdirs.user_config_dir("harpoon")
    if not os.path.isdir(config_dir):
        os.makedirs(config_dir)

    mmdb_path = os.path.join(config_dir, "ip66.mmdb")
    if os.path.isfile(mmdb_path):
        mtime = datetime.fromtimestamp(os.path.getmtime(mmdb_path))
        if datetime.now() - mtime < IP66_MMDB_MAX_AGE:
            return

    print("Downloading latest version of the IP66 database...")
    r = requests.get(IP66_MMDB_URL, stream=True)
    r.raise_for_status()
    tmp_path = mmdb_path + ".tmp"
    with open(tmp_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            f.write(chunk)
    os.replace(tmp_path, mmdb_path)


# Main
# ==============================================================================
def cli():
    config = load_config()
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="Plugins")

    download_needed_files()

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
