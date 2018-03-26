import requests
import json


class CertSpotterError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message


class CertSpotter(object):
    def __init__(self, key=''):
        if key == '':
            self.authenticated = False
        else:
            self.authenticated = True
        self.key = key

    def list(self, domain, expired=False, duplicate=False):
        if expired and not self.authenticated:
            raise CertSpotter("You are not allowed to search fo expired certificate without key")
        if self.authenticated:
            r = requests.get(
                "https://certspotter.com/api/v0/certs",
                params = {'domain': domain, 'expired': expired, 'duplicate': duplicate },
                auth=(self.key, '')
            )
        else:
            r = requests.get(
                "https://certspotter.com/api/v0/certs",
                params = {'domain': domain, 'expired': expired, 'duplicate': duplicate }
            )
        if r.status_code == 200:
            return r.json()
        else:
            raise CertSpotterError("Invalid HTTP status code %i" % r.status_code)

    def get_cert(self, sha256):
        r = requests.get("https://certspotter.com/api/v0/certs/" + sha256)
        if r.status_code == 200:
            return r.json()
        else:
            raise CertSpotterError("Invalid HTTP status code %i" % r.status_code)

    def get_cert_pem(self, sha256):
        r = requests.get("https://certspotter.com/api/v0/certs/" + sha256 + '.pem')
        if r.status_code == 200:
            return r.text
        else:
            raise CertSpotterError("Invalid HTTP status code %i" % r.status_code)

    def get_cert_der(self, sha256):
        r = requests.get("https://certspotter.com/api/v0/certs/" + sha256 + '.der')
        if r.status_code == 200:
            return r.text
        else:
            raise CertSpotterError("Invalid HTTP status code %i" % r.status_code)
