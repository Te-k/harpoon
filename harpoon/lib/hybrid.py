import requests
from requests.auth import HTTPBasicAuth


class HybridAnalysisFailed(Exception):
    pass


class HybridAnalysis(object):
    def __init__(self, key, secret):
        self.key = key
        self.secret = secret
        self.base_url = "https://www.hybrid-analysis.com/api/"
        # Mandatory for Hybrid Analysis (weird)
        self.ua = "Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0"

    def _request(self, path, data={}):
        """
        Query the API with the given path
        """
        headers = { 'User-Agent': self.ua }
        r = requests.get(self.base_url + path, auth=HTTPBasicAuth(self.key, self.secret), headers=headers, params=data)
        if r.status_code != 200:
            raise HybridAnalysisFailed()
        else:
            res = r.json()
            if 'response_code' in res:
                if res['response_code'] == 0:
                    return res['response']
            raise HybridAnalysisFailed()

    def quota(self):
        """
        Query quota information
        """
        return self._request("quota")

    def get_report(self, hash):
        """
        Search for a report for the given hash
        """
        return self._request('scan/' + hash)

    def search(self, query):
        """
        Search for a query in Hybrid Analysis
        """
        return self._request('search', {'query': query})

    def get_summary(self, hash, envid):
        """
        Request the analysis summary
        """
        return self._request('summary/' + hash, data = {'environmentId': envid})

    def get_last_analysis(self, hash):
        """
        Get details from the last analysis
        """
        # Query the hash and then the analysis
        res = self.get_report(hash)
        last = sorted(res, key=lambda x:x['analysis_start_time'], reverse=True)[0]
        return self.get_summary(hash, last['environmentId'])
