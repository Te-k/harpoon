import unittest
from harpoon.lib.utils import unbracket, bracket, same_url, typeguess

class TestUtils(unittest.TestCase):
    def test_bracket(self):
        self.assertEqual(unbracket("domain[.]com"), "domain.com")
        self.assertEqual(bracket("domain.com"), "domain[.]com")

    def test_same_url(self):
        self.assertTrue(same_url("http://example.org", "https://example.org"))
        self.assertTrue(same_url("http://example.org", "http://www.example.org"))
        self.assertFalse(same_url("http://exemple.org", "http://example.org"))

    def test_typeguess(self):
        self.assertEqual(typeguess("44c13fc77ee90ef4040a0c99a9be999e"), "md5")
        self.assertEqual(typeguess("d82b0fffdda6d7120dd8c14da32208278e2a287f"), "sha1")
        self.assertEqual(typeguess("fef75dbbf6297c151a7112cb5f98884e4928716f0725826c42086e6c21a9894d"), "sha256")
        self.assertEqual(typeguess("10.4.4.4"), "IPv4")
        self.assertEqual(typeguess("fce8::1"), "IPv6")
        self.assertEqual(typeguess("domain.com"), "domain")

if __name__ == '__main__':
    unittest.main()
