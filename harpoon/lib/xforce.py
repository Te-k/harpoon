import requests
import base64
import json


class XforceExchangeFailed(Exception):
    pass


class XforceExchangeNotFound(XforceExchangeFailed):
    pass


class XforceExchange(object):
    def __init__(self, api_key, password):
        self.api_key = api_key
        self.password = password
        self.base_url = "https://api.xforce.ibmcloud.com:443"
        self.ua = "Harpoon https://github.com/Te-k/harpoon"

    def _request(self, url, params={}):
        token = base64.b64encode(self.api_key.encode('utf-8') + b":" + self.password.encode('utf-8'))
        headers = {
            'Authorization': "Basic " + token.decode('utf-8'),
            'Accept': 'application/json',
            'User-Agent': self.ua
        }
        r = requests.get(
            self.base_url + url,
            params=params,
            headers=headers
        )
        if r.status_code == 200:
            return r.json()
        else:
            if r.status_code == 404:
                raise XforceExchangeNotFound()
            else:
                print(r.text)
                raise XforceExchangeFailed()

    def ip_reputation(self, ip):
        """
        Returns the IP reputation report for the entered IP.
        """
        return self._request('/ipr/history/' + ip)

    def ip(self, ip):
        """
        Returns the IP report for the entered IP.
        """
        return self._request('/ipr/' + ip)

    def ip_malware(self, ip):
        """
        Returns the malware associated with the entered IP.
        """
        return self._request('/ipr/malware/' + ip)

    def search(self, query):
        """
        Returns a list of public Collections that were found
        """
        return self._request('/casefiles/public/fulltext', params={'q': query})

    def dns(self, _input):
        """
        Returns live and passive DNS records.
        """
        return self._request('/resolve/' + _input)

    def casefile(self, _id):
        """
        Returns a JSON resentation of a Collection
        """
        return self._request('/casefiles/' + _id)

    def malware(self, _hash):
        """
        Returns a malware report for the given file hash, For example, md5,
        sha1 and sha256.
        """
        return self._request('/malware/' + _hash)

    def url(self, url):
        """
        Returns the URL report for the entered URL.
        """
        return self._request('/url/' + url)

    def usage(self):
        """
        Get API usage details per month for each subscription type.
        """
        return self._request('/all-subscriptions/usage')

    def whois(self, domain):
        """
        Returns a JSON object containing information about the given host address.
        """
        return self._request('/whois/' + domain)




