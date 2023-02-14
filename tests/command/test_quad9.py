from harpoon.commands.quad9 import CommandQuad9

from ..utils import launch_plugin


class TestCommandQuad9:
    def test_check(self):
        launch_plugin(
            CommandQuad9,
            ["quad9", "cocospy.com"]
        )
