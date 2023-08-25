from harpoon.plugins.base import HarpoonPlugin


class TestPluginUtils:
    def test_bracket(self):
        hp = HarpoonPlugin(None, None)
        assert hp.unbracket("domain[.]com") == "domain.com"
        assert hp.bracket("domain.com") == "domain[.]com"
