import requests


class IPInfoError(Exception):
    def __init__(self, message):
        self.message = message
        Exception.__init__(self, message)


class IPInfo(object):
    def __init__(self, token):
        self.token = token
        self.base_url = 'https://ipinfo.io/'

    def get_infos(self, ip):
        r = requests.get(self.base_url + ip, params={'token': self.token})
        if r.status_code != 200:
            raise IPInfoError('Invalid HTTP code %i' % r.status_code)
        return r.json()
