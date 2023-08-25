from harpoon.plugins.circl import Circl

from ..utils import launch_plugin


class TestCommandCircl:
    def test_get_ip(self):
        launch_plugin(Circl, ["circl", "amnesty.org"])
