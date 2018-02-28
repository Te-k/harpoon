import argparse
import json
import requests
import os
import sys
try:
    import configparser as cp
except ImportError:
    # python2
    import ConfigParser as cp

class GoogleShortener(object):
    def __init__(self, token):
        self.host = 'https://www.googleapis.com/urlshortener/v1/url'
        self.token = token

    def get_analytics(self, hash):
        params = {'key': self.token, 'shortUrl': 'http://goo.gl/' + hash, 'projection': 'FULL'}
        r = requests.get(self.host, params=params)
        return r.json()

    def expand(self, hash):
        params = {'key': self.token, 'shortUrl': 'http://goo.gl/' + hash}
        r = requests.get(self.host, params=params)
        return r.json()

    def shorten(self, long_url):
        params = {'key': self.token, 'longUrl': long_url}
        r = requests.post(self.host, data=params)
        return r.json()
