from harpoon.commands.hashlookup import CommandHashLookup
from ..utils import launch_plugin


class TestCommandHashLookup:
    def test_hash(self):
        launch_plugin(
            CommandHashLookup,
            ["hashlookup", "hash", "8ED4B4ED952526D89899E723F3488DE4"]
        )
