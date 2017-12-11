import unittest
from harpoon.lib.bing import Bing

class TestBing(unittest.TestCase):
    def test_search(self):
        b = Bing()
        res = b.search("test")
        self.assertEqual(len(res), 10)

    def test_cache(self):
        b = Bing()
        res = b.cache("https://www.test.com")
        self.assertEqual(res["success"], True)

if __name__ == '__main__':
    unittest.main()
