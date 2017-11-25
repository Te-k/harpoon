import unittest
from harpoon.lib.google import Google

class TestGoogle(unittest.TestCase):
    def test_search(self):
        g = Google()
        res = g.search('test')
        self.assertEqual(len(res), 10)

if __name__ == '__main__':
    unittest.main()
