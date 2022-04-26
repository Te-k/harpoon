import requests


class PithusError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message

class PithusQuotaExceeded(PithusError):
    pass

class Pithus(object):
    def __init__(self, key=None):
        self.url = "https://beta.pithus.org/api/"
        self.api_key = key
        self.headers = {
                "User-Agent": "Harpoon (https://github.com/Te-k/harpoon)",
                "Content-Type": "application/json"
                }
        if self.api_key:
            self.headers['Authorization'] = 'Token ' + self.api_key
        else: 
            PithusError("Missing token, visit beta.pithus.org/hunting to retrieve it")

    def handle_request(self, r):
        print("########")
        print(r)
        print("########")
        if r.status_code == 200:
            print(r)
        elif r.status_code == 404:
            raise PithusError("Report not found")
        elif r.status_code == 453:
            raise PithusQuotaExceeded("Quota exceeded")
        elif r.status_code != 200 or r.status_code != 453:
            raise PithusError(r)
        else:
            raise PithusError('Invalid HTTP Code returned: {}'.format(r.status_code))


    def _get(self, url, params):
        r = requests.get(url, json=params, headers=self.headers)
        self.handle_request(r)

    def _post(self, url, params):
        r = requests.post(url, json=params, headers=self.headers)
        self.handle_request(r)

    def report(self, query):
        params = {
                "q": query,
                }
        return self._get(self.url + "report/", params)


    def status(self, query):
        params = {
                "q": query, 
                }
        return self._get(self.url + "status/", params)


    def upload(self, query):
        params = {
                "q": query, 
                }
        return self_post(self.url + "upload/", params)


    def search(self, query):
        params = {
                "q": query,
                }
        return self._post(self.url + "search/", params)
