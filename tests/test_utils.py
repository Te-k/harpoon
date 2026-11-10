from harpoon.lib.utils import bracket, same_url, typeguess, unbracket


class TestUtils:
    def test_bracket(self):
        assert unbracket("domain[.]com") == "domain.com"
        assert bracket("domain.com") == "domain[.]com"

    def test_bracket_without_dot(self):
        # A domain without a dot (e.g. "localhost") has nothing to
        # bracket and must be returned unchanged
        assert bracket("localhost") == "localhost"
        assert bracket("") == ""

    def test_same_url(self):
        assert same_url("http://example.org", "https://example.org")
        assert same_url("http://example.org", "http://www.example.org")
        assert same_url("http://exemple.org", "http://example.org") is False

    def test_typeguess(self):
        assert typeguess("44c13fc77ee90ef4040a0c99a9be999e") == "md5"
        assert typeguess("d82b0fffdda6d7120dd8c14da32208278e2a287f") == "sha1"
        assert typeguess("fef75dbbf6297c151a7112cb5f98884e4928716f0725826c42086e6c21a9894d") == "sha256"
        assert typeguess("10.4.4.4") == "IPv4"
        assert typeguess("fce8::1") == "IPv6"
        assert typeguess("domain.com") == "domain"
