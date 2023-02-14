import requests

from harpoon.lib.utils import is_sha256


class HybridAnalysisFailed(Exception):
    pass


class HybridAnalysisInvalidQuery(Exception):
    pass


class HybridAnalysis(object):
    def __init__(self, key):
        self.key = key
        self.base_url = "https://www.hybrid-analysis.com/api/v2/"
        # Mandatory for Hybrid Analysis (weird)
        self.ua = "Falcon Sandbox"

    def _get(self, path):
        """
        Query the API with the given path
        """
        headers = {
            "User-Agent": self.ua,
            "api-key": self.key
        }
        r = requests.get(
            self.base_url + path,
            headers=headers
        )
        if r.status_code != 200:
            raise HybridAnalysisFailed()
        else:
            return r.json()

    def _post(self, path, data={}):
        """
        Query the API with the given path
        """
        headers = {
            "User-Agent": self.ua,
            "api-key": self.key
        }
        r = requests.post(
            self.base_url + path,
            headers=headers,
            data=data
        )
        if r.status_code != 200:
            raise HybridAnalysisFailed()
        else:
            return r.json()

    # --------------------------- search --------------------------------------
    def search_hash(self, hash):
        """
        Summary for a given hash
        hash should be md5, sha1 or SHA256
        """
        return self._post(
            "search/hash",
            data={"hash": hash}
        )

    def search_terms(self, data):
        """
        Search the database using search terms
        Accepted keywords :
        filename
        filetype
        filetype_desc
        env_id
        country
        verdict
        av_detect
        vx_family
        date_from
        date_to
        port
        host
        domain
        url
        similar_to
        context
        imp_hash
        ssdeep
        authentihash
        uses_tactics
        uses_tecnique
        """
        terms = [
            "filename", "filetype", "filetype_desc", "env_id", " country",
            "verdict", "av_detect", "vx_family", "date_from", "date_to",
            "port", "host", "domain", "url", "similar_to", "context",
            "imp_hash", "ssdeep", "authentihash", "uses_tactics", "uses_tecnique"]
        for d in data:
            if d not in terms:
                raise HybridAnalysisInvalidQuery("{} is not a valid search term".format(d))

        return self._post("search/terms", data)

        # ------------------------------- Overview --------------------------------
    def overview_hash(self, hash):
        """
        Return overview of a hash
        /overview/{sha256}
        """
        if not is_sha256(hash):
            raise HybridAnalysisInvalidQuery("Invalid sha256 format")
        return self._get('overview/' + hash)

    def overview_summary(self, hash):
        """
        Returns overview for a hash
        /overview/{sha256}/summary
        """
        if not is_sha256(hash):
            raise HybridAnalysisInvalidQuery("Invalid sha256 format")
        return self._get('overview/' + hash + "/summary")

    def overview_sample(self, hash):
        """
        Download a sample
        """
        if not is_sha256(hash):
            raise HybridAnalysisInvalidQuery("Invalid sha256 format")
        headers = {
            "User-Agent": self.ua,
            "api-key": self.key
        }
        r = requests.get(
            self.base_url + "overview/" + hash + "/sample",
            headers=headers,
        )
        if r.status_code != 200:
            raise HybridAnalysisFailed()
        else:
            return r.content
