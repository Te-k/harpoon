from harpoon.commands.netapi import CommandNetAPI

from ..utils import launch_plugin


class TestCommandNetAPI:
    def test_domain(self):
        launch_plugin(
            CommandNetAPI,
            ["netapi", "domain", "google.com"]
        )

    def test_tld(self):
        launch_plugin(
            CommandNetAPI,
            ["netapi", "tld", "com"]
        )
