import requests


class ThreatCrowdError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message


class ThreatCrowd(object):
    """
    ThreatCrowd API handler
    https://github.com/AlienVault-OTX/ApiV2
    """
    def __init__(self):
        self.base_url = "http://www.threatcrowd.org/searchApi/v2/"

    def _query(self, queryType, query):
        if queryType == "file":
            res = requests.get(
                self.base_url + queryType + "/report/", {"resource": query}
            )
        else:
            res = requests.get(
                self.base_url + queryType + "/report/", {queryType: query}
            )
        if res.status_code != 200:
            raise ThreatCrowdError("Erorr: HTTP code {}".format(res.status_code))
        return res.json()

    def ip(self, ip):
        """
        get info on an IP address
        """
        return self._query("ip", ip)

    def email(self, email):
        return self._query("email", email)

    def domain(self, domain):
        return self._query("domain", domain)

    def antivirus(self, av):
        return self._query("antivirus", av)

    def file(self, ffile):
        return self._query("file", ffile)
