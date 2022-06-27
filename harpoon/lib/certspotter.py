import requests
from requests.auth import HTTPBasicAuth


class CertSpotterError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message


class CertSpotter(object):
    def __init__(self, key=None):
        self.key = key
        self.base_url = "https://api.certspotter.com/"

    @property
    def authenticated(self):
        return (self.key is not None)

    def _get(self, query, params={}):
        if self.authenticated:
            r = requests.get(
                self.base_url + query,
                params=params,
                auth=HTTPBasicAuth(self.key, "")
            )
        else:
            r = requests.get(
                self.base_url + query,
                params=params
            )
        if r.status_code == 200:
            return r.json()
        else:
            raise CertSpotterError("Invalid HTTP status code %i" % r.status_code)

    def search(self, domain, include_subdomains=False):
        return self._get(
                "v1/issuances",
                params={
                    "domain": domain,
                    "expand": ["dns_names", "issuer", "cert"],
                    "include_subdomains": include_subdomains})
