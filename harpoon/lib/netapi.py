import requests


class NetAPIError(Exception):
    def __init__(self, message, code=None, status=None):
        self.message = message
        self.code = code
        self.status = status
        Exception.__init__(self, message)


class NetAPI:
    """
    Client for the NetAPI JSON API (https://netapi.com/help/api/#json-api)

    The methods used here are free and need no key. An API token of a NetAPI
    account can be given to raise the request limits.
    """

    def __init__(self, key=None):
        self.key = key
        self.base_url = "https://netapi.com/api-json/"
        self.headers = {"User-Agent": "harpoon (https://github.com/Te-k/harpoon)"}
        if key:
            self.headers["Authorization"] = "Bearer {}".format(key)

    def _get(self, method, params):
        params["method"] = method
        r = requests.get(self.base_url, params=params, headers=self.headers, timeout=30)
        if r.status_code != 200:
            try:
                error = r.json()["error"]
                message = error.get("message", "")
                code = error.get("code")
            except (ValueError, KeyError, TypeError):
                message = "Invalid HTTP code {}".format(r.status_code)
                code = None
            if r.status_code == 429 and "Retry-After" in r.headers:
                message += " Retry after {} seconds.".format(r.headers["Retry-After"])
            raise NetAPIError(message, code=code, status=r.status_code)
        return r.json()

    def domain_rank(self, domain):
        """
        Rank of a domain in the NetAPI Top 1M list
        """
        return self._get("domain-rank", {"domain": domain})

    def compromised_check(self, value):
        """
        Check a domain or an IP address against the NetAPI compromised feed
        """
        return self._get("compromised-check", {"value": value})

    def search_new(self, query, days=7, tld=None, match="contains", limit=100):
        """
        Search the domains registered in the last days (1 to 7)
        """
        params = {"q": query, "days": days, "match": match, "limit": limit}
        if tld:
            params["tld"] = tld
        return self._get("search-new", params)

    def tld_stats(self, tld):
        """
        Figures of a TLD: domains, daily changes, compromised share, Top 1M presence
        """
        return self._get("tld-stats", {"tld": tld})
