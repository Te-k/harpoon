import json

import requests
from simplejson.errors import JSONDecodeError


class DNSDBError(Exception):
    def __init__(self, message):
        self.message = message
        Exception.__init__(self, message)


class DNSDBInvalidParameters(Exception):
    pass


class DnsDB(object):
    """
    Implementation of Farsight DNSDB API
    See https://docs.farsightsecurity.com/dnsdb/dnsdb-apiv2/
    """
    def __init__(self, token):
        self.token = token
        self.base_url = "https://api.dnsdb.info/"

    def _get(self, query, params={}):
        headers = {
            "User-Agent": "harpoon (https://github.com/Te-k/harpoon/)",
            "X-API-Key": self.token
        }
        r = requests.get(self.base_url + query, headers=headers)
        if r.status_code != 200:
            raise DNSDBError('Invalid HTTP code %i' % r.status_code)
        try:
            return r.json()
        except JSONDecodeError:
            # JSONL
            res = []
            for line in r.text.split("\n"):
                if line.strip() == "":
                    continue
                dd = json.loads(line)
                if "obj" in dd:
                    res.append(dd["obj"])
        return res

    def ping(self):
        return self._get("dnsdb/v2/ping")

    def rrset_lookup(self, value, rrtype="ANY"):
        return self._get("dnsdb/v2/lookup/rrset/name/{}/{}".format(value, rrtype))

    def rdata_lookup(self, value, type="name", rrtype="ANY"):
        if type not in ["name", "ip", "raw"]:
            raise DNSDBInvalidParameters("Invalid type parameter")
        return self._get("dnsdb/v2/lookup/rdata/{}/{}/{}".format(type, value, rrtype))
