from harpoon.commands.safebrowsing import CommandSafeBrowsing
from ..utils import launch_plugin


class TestCommandSafeBrowsing:
    def test_check(self):
        launch_plugin(
            CommandSafeBrowsing,
            ["safebrowsing", "url", "http://malware.testing.google.test/testing/malware/"]
        )
