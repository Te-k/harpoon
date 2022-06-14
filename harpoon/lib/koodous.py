import requests


class KoodousError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message


class KoodousNotFound(KoodousError):
    pass


class Koodous(object):
    def __init__(self, token=None):
        self.token = token
        self.base_url = "https://developer.koodous.com"

    def _query(self, url, params={}):
        headers = {
            "Authorization": "Token " + self.token,
            'User-Agent': 'Harpoon (https://github.com/Te-k/harpoon)'
        }
        r = requests.get(self.base_url + url, params=params, headers=headers)
        if r.status_code == 404:
            raise KoodousNotFound()
        elif r.status_code != 200:
            raise KoodousError("Invalid HTTP code {} - {}".format(r.status_code, r.text))
        return r.json()

    def sha256(self, hash):
        return self._query("/apks/" + hash)

    def search(self, query):
        return self._query("/apks/", {'search': query})

    def download(self, hash):
        headers = {
            "Authorization": "Token " + self.token,
            'User-Agent': 'Harpoon (https://github.com/Te-k/harpoon)'
        }
        r = requests.get(
            self.base_url + "/apks/" + hash + "/download/",
            headers=headers)
        if r.status_code == 404:
            raise KoodousNotFound()
        elif r.status_code != 200:
            raise KoodousError("Invalid HTTP code {}".format(r.status_code))
        return r.content

    def analysis(self, hash):
        return self._query("/apks/" + hash + "/analysis")

    def account(self):
        return self._query("/account/")
