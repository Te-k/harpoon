import requests


class CyberCureError(Exception):
    def __init__(self, message):
        self.message = message
        Exception.__init__(self, message)


class CyberCure(object):
    def __init__(self, token):
        self.token = token
        self.base_url = 'http://api.cybercure.ai/feed/search?value='

    def get_infos(self, ip):
        r = requests.get(self.base_url + ip, headers={'User-Agent': 'harpoon (https://github.com/Te-k/harpoon/)'})
        if r.status_code != 200:
            raise CyberCureError('Invalid HTTP code %i' % r.status_code)
        return r.json()
