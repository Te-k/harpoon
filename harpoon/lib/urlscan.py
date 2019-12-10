import requests

class UrlScan(object):
    def __init__(self):
        self.url = "https://urlscan.io/api/v1/"

    def search(self, query, size=100, offset=0):
        params = {
            'q': query,
            'size': size,
            'offset': offset
        }
        r = requests.get(self.url + "search/", params=params)
        return r.json()

    def view(self, uid):
        r = requests.get(self.url + 'result/' + uid)
        return r.json()

