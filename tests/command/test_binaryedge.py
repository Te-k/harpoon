from harpoon.commands.binaryedge import CommandBinaryEdge

from ..utils import launch_plugin


class TestCommandBinaryEdge:
    def test_get_ip(self):
        launch_plugin(
            CommandBinaryEdge,
            ["binaryedge", "ip", "162.55.191.113"]
        )
