import requests


class PulseDiveError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message

class PulseDiveNotFound(PulseDiveError):
    pass


class PulseDive(object):
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://pulsedive.com/api/"

    def _query(self, url, params):
        if self.api_key:
            params["key"] = self.api_key

        headers = {'User-Agent': 'Harpoon (https://github.com/Te-k/harpoon)'}
        r = requests.get(
            self.base_url + url,
            params=params,
            headers=headers
        )
        if r.status_code == 404:
            raise PulseDiveNotFound("Not found")
        elif r.status_code != 200:
            raise PulseDiveError("Bad HTTP Response {}".format(r.status_code))
        return r.json()

    def indicators_by_value(self, val, historical=False):
        """
        This query is identical to querying by indicator ID, but the
        information is retrieved using the indicator value. Querying
        links and properties by indicator value won't work.
        """
        params  = {'indicator': val}
        if historical:
            params['historical'] = "1"
        return self._query("info.php", params)

    def indicators_by_value_links(self, val):
        return self._query("info.php", {'indicator': val, "get": "links"})

    def indicators_by_value_properties(self, val):
        return self._query("info.php", {'indicator': val, "get": "properties"})

    def threat(self, threat):
        return self._query("info.php", {'threat': threat})

    def threat_indicators(self, tid):
        return self._query("info.php", {'tid': tid, 'get': 'links'})



