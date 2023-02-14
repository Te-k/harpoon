import base64

import requests


class PhishtankError(Exception):
    pass


class Phishtank:
    def __init__(self, key=None):
        self.url = "https://checkurl.phishtank.com/checkurl/"
        self.headers = {
            "User-Agent": "Harpoon (https://github.com/Te-k/harpoon)",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        self.key = key

    def query(self, url):
        post_data = {
            "url": base64.b64encode(url.encode("utf-8")),
            "format": "json",
        }
        if self.key:
            post_data["app_key"] = self.key
        r = requests.post(
            self.url,
            data=post_data,
            headers=self.headers)
        if r.status_code != 200:
            raise PhishtankError("Wrong HTTP code {}".format(r.status_code))
        return r.json()
