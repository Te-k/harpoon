import requests


class UrlScanError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message


class UrlScanQuotaExceeded(UrlScanError):
    pass


class UrlScan(object):
    def __init__(self, key=None):
        self.url = "https://urlscan.io/api/v1/"
        self.api_key = key

    def _get(self, url, params):
        headers = {
            "User-Agent": "phishtank/Harpoon (https://github.com/Te-k/harpoon)",
            "Content-Type": "application/json"
        }
        if self.api_key:
            headers["API-Key"] = self.api_key
        r = requests.get(url, params=params, headers=headers)
        if r.status_code != 200:
            if r.status_code == 429:
                if "message" in r.json():
                    raise UrlScanQuotaExceeded(r.json()["message"])
                else:
                    raise UrlScanQuotaExceeded("Quota exceeded")
            else:
                raise UrlScanError(
                    "Invalid HTTP Code returned: {}".format(r.status_code))
        res = r.json()
        if "status" in res:
            if res['status'] == 429:
                raise UrlScanQuotaExceeded(res["message"])
        return res

    def search(self, query, size=100, offset=0):
        params = {
            'q': query,
        }
        return self._get(self.url + "search/", params)

    def view(self, uid):
        return self._get(self.url + "result/" + uid, {})

    def quota(self):
        return self._get("https://urlscan.io/user/quotas/", {})
