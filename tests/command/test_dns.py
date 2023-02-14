from harpoon.commands.dnsc import CommandDns
from harpoon.commands.ip import CommandIp

from ..utils import launch_plugin


class TestCommandDns:
    def pending_get_query(self):
        launch_plugin(
            CommandDns,
            ["dns", "google.com"],
            plugins={"ip": CommandIp({})}
        )
