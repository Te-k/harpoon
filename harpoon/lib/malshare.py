import requests
import json


class MalShareFailed(Exception):
    pass


class MalShareNotFound(MalShareFailed):
    pass


class MalShareSampleMissing(MalShareFailed):
    pass


class MalShare(object):
    def __init__(self, key):
        self.key = key
        self.base_url = "https://malshare.com/api.php"
        self.ua = "Harpoon"

    def _request(self, params):
        params['api_key'] = self.key
        headers = { 'User-Agent': self.ua }
        r = requests.get(
            self.base_url,
            params=params,
            headers=headers
        )
        if r.status_code == 200:
            return r
        else:
            raise MalShareFailed()

    def list_last24h_samples(self):
        params = {'action': 'getlistraw'}
        r = self._request(params)
        return r.text.strip().split("\n")

    def list_last24h_sources(self):
        params = {'action': 'getsourcesraw'}
        r = self._request(params)
        return r.strip().split("\n")

    def download(self, hash):
        """
        Download file
        """
        data = self._request({'action': 'getfile', 'hash': hash})
        if "Sample not found" in data.text:
            raise MalShareNotFound()
        else:
            if "Error => Sample Missing":
                raise MalShareSampleMissing()
            else:
                return data.text

    def file_info(self, hash):
        """
        Get information on the file
        """
        data = self._request({'action': 'details', 'hash': hash})
        if "Sample not found" in data.text:
            raise MalShareNotFound()
        else:
            return data.json()

    def search(self, query):
        data = self._request({'action': 'search', 'query': query})
        if data.text == '':
            return {}
        else:
            return [json.loads(a) for a in data.text.strip().split('\n')]
