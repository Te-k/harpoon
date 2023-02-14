from harpoon.commands.hybrid import CommandHybridAnalysis

from ..utils import launch_plugin


class TestCommandHybridAnalysis:
    def test_search_hash(self):
        launch_plugin(
            CommandHybridAnalysis,
            ["hybrid", "hash", "c426ba56ecb2cc4e7259f14a69ffb139c659d9072164e78744cf9cf2fc0e8527"]
        )

    def test_search_domain(self):
        launch_plugin(
            CommandHybridAnalysis,
            ["hybrid", "ip", "35.188.42.15"]
        )
