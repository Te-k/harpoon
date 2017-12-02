from datetime import datetime
import json
import requests


class RobtexError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message


class Robtex(object):
    """
    Library to request Robtex API
    https://www.robtex.com/api/
    """
    def _request(self, path):
        r = requests.get("https://freeapi.robtex.com" + path)
        if r.status_code != 200:
            raise RobtexError("Wrong HTTP status code %i" % r.status_code)
        else:
            data = r.json()
            if "status" not in data:
                raise RobtexError("Wrong message format")
            else:
                if data["status"] != "ok":
                    raise RobtexError("Wrong status code %s" % data["status"])
                else:
                    return data

    def _parse_pdns(self, data):
        return [json.loads(a) for a in data.split()]

    def get_ip_info(self, ip):
        """
        Request info on an IPv4
        """
        data = self._request("/ipquery/%s" % ip)
        for d in ["pas", "pash", "act", "acth"]:
            if d in data:
                for dd in data[d]:
                    if "t" in dd:
                        dd["date"] = datetime.fromtimestamp(dd["t"])
        return data

    def get_asn_info(self, asn):
        """
        Get ASN info
        """
        return self._request("/asquery/%i" % asn)

    def get_pdns_domain(self, domain):
        """
        Get passive DNS info on a domain
        """
        r = requests.get("https://freeapi.robtex.com/pdns/forward/%s" % domain)
        if r.status_code != 200:
            raise RobtexError("Wrong HTTP status code %i" % r.status_code)
        else:
            data = self._parse_pdns(r.text)
            for d in data:
                if "time_first" in d:
                    d["time_first_o"] = datetime.fromtimestamp(d["time_first"])
                if "time_last" in d:
                    d["time_last_o"] = datetime.fromtimestamp(d["time_last"])

            return data

    def get_pdns_ip(self, ip):
        """
        Get passive DNS info on an IP address
        """
        r = requests.get("https://freeapi.robtex.com/pdns/reverse/%s" % ip)
        if r.status_code != 200:
            raise RobtexError("Wrong HTTP status code %i" % r.status_code)
        else:
            data = self._parse_pdns(r.text)
            for d in data:
                if "time_first" in d:
                    d["time_first_o"] = datetime.fromtimestamp(d["time_first"])
                if "time_last" in d:
                    d["time_last_o"] = datetime.fromtimestamp(d["time_last"])

            return data
