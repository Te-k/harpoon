import requests
import json


class HibpError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message


class HibpNotFound(HibpError):
    def __init__(self):
        HibpError.__init__(self, "Account Not Found in the database")


class HIBP(object):
    """
    Object to request the Have I Been Pwned API
    https://haveibeenpwned.com/API/v2#BreachesForAccount
    """
    def __init__(self):
        self.ua = "Harpoon"

    def _request(self, query):
        """
        Request an url
        """
        r = requests.get('https://haveibeenpwned.com' + query, headers= {'User-Agent': self.ua})
        if r.status_code != 200:
            if r.status_code == 404:
                raise HibpNotFound()
            else:
                raise HibpError('Invalid HTTP status code %i' % r.status_code)
        return r

    def get_breaches_account(self, account):
        return self._request('/api/v2/breachedaccount/%s' % account).json()

    def list_breaches(self):
        """List all breaches"""
        return self._request('/api/v2/breaches').json()

    def get_breach(self, breach):
        return self._request('/api/v2/breach/%s' % breach).json()

    def get_dataclasses(self):
        return self._request('/api/v2/dataclasses').json()

    def get_pastes(self, account):
        return self._request('/api/v2/pasteaccount/%s' % account).json()

    def check_pwd(self, pwd):
        return self._request('/api/v2/pwnedpassword/%s' % pwd).json()

