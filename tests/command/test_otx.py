from harpoon.commands.otx import CommandOtx

from ..utils import launch_plugin


class TestCommandOtx:
    def test_search(self):
        launch_plugin(
            CommandOtx,
            ["otx", "-s", "37.49.230.155"]
        )

    def test_pulse(self):
        launch_plugin(
            CommandOtx,
            ["otx", "-p", "61b72e243e746d2994b3ba54"]
        )
