from harpoon.commands.phishtank import CommandPhishtank

from ..utils import launch_plugin


class TestCommandPhishtank:
    def test_query(self):
        launch_plugin(
            CommandPhishtank,
            ["phishtank", "https://h5.wpasoir.top/"]
        )
