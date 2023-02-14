from harpoon.commands.circl import CommandCircl

from ..utils import launch_plugin


class TestCommandCircl:
    def test_get_ip(self):
        launch_plugin(
            CommandCircl,
            ["circl", "amnesty.org"]
        )
