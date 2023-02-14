from harpoon.commands.shodancmd import CommandShodan

from ..utils import launch_plugin


class TestCommandShodan:
    def test_get_quota(self):
        launch_plugin(
            CommandShodan,
            ["shodan", "quota"]
        )

    def test_ip(self):
        launch_plugin(
            CommandShodan,
            ["shodan", "ip", "162.55.191.113"]
        )

    def test_search(self):
        launch_plugin(
            CommandShodan,
            ["shodan", "search", "IPCamera_Logo"]
        )

    def test_ssh(self):
        launch_plugin(
            CommandShodan,
            ["shodan", "ssh", "45.55.57.98"]
        )
