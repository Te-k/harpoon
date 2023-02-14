from harpoon.commands.dnsdbcmd import DnsDbTotal

from ..utils import launch_plugin


class TestDnsDbTotal:
    def test_get_domains(self):
        launch_plugin(
            DnsDbTotal,
            ["dnsdb", "ip", "162.55.191.113"]
        )

    def test_get_ips(self):
        launch_plugin(
            DnsDbTotal,
            ["dnsdb", "domain", "randhome.io"]
        )
