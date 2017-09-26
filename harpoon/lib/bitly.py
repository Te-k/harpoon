import argparse
import json
import requests
import os
import sys
import datetime
import logging
try:
    from urllib.parse import urljoin
except ImportError:
    # python2
    from urlparse import urljoin
try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client
try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser


class Error(Exception):
    pass


class BitlyError(Error):
    def __init__(self, code, message):
        Error.__init__(self, message)
        self.code = code


class Bitly(object):
    """
    Python class managing bitly API calls
    Mostly inspired from https://github.com/bitly/bitly-api-python
    """

    def __init__(self, access_token):
        self.access_token = access_token
        self.host = 'https://api-ssl.bit.ly/'
        self.linkbase = "http://bit.ly/"

    def _apicall(self, url, params={}):
        params["access_token"] = self.access_token
        r = requests.get(urljoin(self.host, url), params=params)
        data = r.json()
        if data["status_code"] == 200:
            return data['data']
        else:
            raise BitlyError(data["status_code"], data["status_txt"])

    def pprint(self, data):
        print(
            json.dumps(
                data,
                sort_keys=True,
                indent=4,
                separators=(',', ': ')
            )
        )

    def user_info(self, login=None):
        if login is not None:
            return self._apicall("/v3/user/info", params={"login": login})
        else:
            return self._apicall("/v3/user/info")

    def user_link_history(self, user=None):
        if user is not None:
            return self._apicall("/v3/user/link_history", params={"user": user})
        else:
            return self._apicall("/v3/user/link_history")

    def info(self, hash):
        return self._apicall("/v3/info", {"shortUrl": self.linkbase + hash, "expand_user": True})

    def link_expand(self, hash):
        return self._apicall("/v3/expand", {"shortUrl": self.linkbase + hash})

    def link_info(self, hash):
        return self._apicall("/v3/link/info", {"link": self.linkbase + hash})

    def link_clicks(self, hash):
        return self._apicall("/v3/link/clicks", {"link": self.linkbase + hash})

    def link_countries(self, hash):
        return self._apicall("/v3/link/countries", {"link": self.linkbase + hash})

    def link_referrers(self, hash):
        return self._apicall("/v3/link/referrers", {"link": self.linkbase + hash})

    def link_encoders(self, hash):
        return self._apicall("/v3/link/encoders", {"link": self.linkbase + hash, "expand_user": True})

    def link_encoders_by_count(self, hash):
        return self._apicall("/v3/link/encoders_by_count", {"link": self.linkbase + hash})

    def link_encoders_count(self, hash):
        return self._apicall("/v3/link/encoders_count", {"link": self.linkbase + hash})

    def link_lookup(self, long_url):
        return self._apicall("/v3/user/link_lookup", {"url": long_url})


class Link(object):
    def __init__(self, api, hash):
        self._hash = hash.strip()
        self._api = api
        self._clicks = None
        self._is_aggregate = None
        self._aggregate = None
        self._user_hash = None
        self._is_user_valid = None
        self._user_info = None
        self._title = None
        self._timestamp = None
        self._referrers = None
        self._countries = None
        self._encoders_count = None
        self._long_url = None
        self._infos = None

    @property
    def short_url(self):
        return ("http://bit.ly/%s" % self.hash)

    @property
    def long_url(self):
        if self._long_url is None:
            res = self._api.link_expand(self.hash)
            if len(res["expand"]) > 1:
                print("Too much data here, weird...")
            data = res["expand"][0]

            self._long_url = data["long_url"]
            if self._is_aggregate is None:
                if data["global_hash"] == self.hash:
                    self._is_aggregate = True
                else:
                    self._is_aggregate = False
                    self._aggregate = Link(self._api, data["global_hash"])
                if self._user_hash is None:
                    self._user_hash = data["user_hash"]
        return self._long_url

    @property
    def is_user_valid(self):
        if self._is_user_valid is None:
            try:
                data = self._api.user_info(self.user_hash)
                self._is_user_valid = True
                self._user_info = data
            except BitlyError:
                self._is_user_valid = False

    @property
    def infos(self):
        if self._infos is None:
            self._infos = self._api.link_info(self.hash)
        return self._infos

    @property
    def user_info(self):
        if self._user_info is None:
            self.is_user_valid
        return self._user_info

    @property
    def hash(self):
        return self._hash

    @property
    def clicks(self):
        if self._clicks is None:
            data = self._api.link_clicks(self.hash)
            self._clicks = data["link_clicks"]
        return self._clicks

    @property
    def is_aggregate(self):
        if self._is_aggregate is None:
            self._get_infos()
        return self._is_aggregate

    @property
    def aggregate(self):
        if self._is_aggregate is None:
            self._get_infos()
        return self._aggregate

    @property
    def title(self):
        if self._is_aggregate is None:
            self._get_infos()
        return self.title

    @property
    def timestamp(self):
        if self._timestamp is None:
            self._get_infos()
        return self._timestamp

    @property
    def referrers(self):
        if self._referrers is None:
            data = self._api.link_referrers(self.hash)
            self._referrers = data["referrers"]
        return self._referrers

    @property
    def countries(self):
        if self._countries is None:
            data = self._api.link_countries(self.hash)
            self._countries = data["countries"]
        return self._countries

    @property
    def encoders_count(self):
        if self._encoders_count is None:
            data = self._api.link_encoders_count(self.hash)
            self._encoders_count = data["count"]
            if self._aggregate is None:
                self._aggregate = Link(self._api, data["aggregate_link"][-6:])
        return self._encoders_count

    @property
    def user_hash(self):
        if self._user_hash is None:
            self._get_infos()
        return self._user_hash

    def _get_infos(self):
        res = self._api.info(self.hash)
        data = res["info"][0]
        if len(res["info"]) > 1:
            # FIXME : logger here
            print("More than one info for this link, weird")
        self._timestamp = datetime.datetime.fromtimestamp(data["created_at"])
        if data["global_hash"] == self.hash:
            self._is_aggregate = True
        else:
            self._is_aggregate = False
            self._aggregate = Link(self._api, data["global_hash"])
        self._title = data["title"]
        self._user_hash = data["user_hash"]

    def __repr__(self):
        return "%s(%s)" % ("Link", self.short_url)

    def pprint(self):
        print("-------------------- Bit.ly Link infos -------------------")
        print("# INFO")
        print("Link: %s\t\tMetrics: %s+" % (self.short_url, self.short_url))
        print("Expanded url: %s" % self.long_url)
        print("Creation Date: %s" % str(self.timestamp))
        if self.is_aggregate:
            print("Aggregate link")
        else:
            print("Aggregate link: %s" % self.aggregate.short_url)
        print("%i bitly redirect to this url" % self.encoders_count)
        print("\n# LINK  INFO")
        for i in self.infos:
            print("%s: %s" % (i, self.infos[i]))

        print("\n# USERS")
        print("User: %s" % self.user_hash)
        if self.is_user_valid:
            print("Valid user:")
            for p in self.user_info:
                print("\t%s : %s" % (p, self.user_info[p]))
        else:
            print("Invalid user!")
        print("\n# CLICKS")
        print("%i clicks on this link" % self.clicks)
        print("\n# COUNTRIES")
        for c in self.countries:
            print("-%s: %i clicks" % (c["country"], c["clicks"]))
        print("\n# REFERRERS")
        for r in self.referrers:
            if "referrer" in r:
                print("-%s: %i clicks" % (r["referrer"], r["clicks"]))
            else:
                print("-%s (%s): %i clicks" % (r["referrer_app"], r["url"], r["clicks"]))
