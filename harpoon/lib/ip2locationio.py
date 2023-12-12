import requests

class IP2LocationioError(Exception):
    def __init__(self, message):
        self.message = message
        Exception.__init__(self, message)

class IP2Locationio(object):
    def __init__(self, token):
        self.token = token
        self.base_url = 'https://api.ip2location.io/'

    def get_infos(self, ip):
        r = requests.get(self.base_url , params={'key': self.token, 'ip': ip})
        if r.status_code != 200:
            raise IP2LocationioError('Invalid HTTP code %i' % r.status_code)
        return r.json()
