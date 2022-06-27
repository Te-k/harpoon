from harpoon.commands.crtsh import CommandCertsh
from ..utils import launch_plugin


class TestCommandCertsh:
    def test_get_cert(self):
        launch_plugin(
            CommandCertsh,
            ["crtsh", "cert", "72440953"]
        )
