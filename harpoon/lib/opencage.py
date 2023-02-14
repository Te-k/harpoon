from urllib import parse

import requests


class OpenCageError(Exception):
    pass


class RateLimitExceededError(OpenCageError):
    pass


class OpenCage:
    def __init__(self, key):
        self.url = 'http://api.opencagedata.com/geocode/v1/json'
        self.key = key

    def _request(self, params):
        params["key"] = self.key
        r = requests.get(
            self.url,
            params=params
        )
        if r.status_code != 200:
            if (r.status_code == 402 or r.status_code == 429):
                raise RateLimitExceededError()
            else:
                raise OpenCageError()
        return r.json()

    def reverse(self, lat, long):
        """
        Find the address closest to a location
        """
        params = {
            "q": "{}%2C%20{}".format(lat, long),
            "language": "en"
        }
        return self._request(params)

    def geocode(self, place):
        params = {
            "q": parse.quote(place),
            "language": "en"
        }
        return self._request(params)
