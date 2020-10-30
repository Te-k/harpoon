#! /usr/bin/env python3

import re

import requests
from dateutil.parser import parse


class UrlHausError(Exception):
    pass


class UrlHaus(object):
    """
    urlhaus.abuse.ch API Wrapper

    API documentation:
    * https://urlhaus-api.abuse.ch/#urlinfo
    * https://urlhaus.abuse.ch/api/#retrieve
    """

    def __init__(self, key):
        self.key = key
        self.base_url = "https://urlhaus-api.abuse.ch/v1/"

    def _query(self, query):
        return requests.get(self.base_url + query)

    def launch_post_query(self, url, key, query):
        """
        Wrapper for POST queries
        """
        try:
            r = requests.post(
                url,
                headers={"User-Agent": "urlhaus-harpoon"},
                data={key: query},
            )
            if r.ok:
                return r.json()
            else:
                raise UrlHausError()
        except Exception as e:
            raise UrlHausError(e)

    def download_sample(self, url, query):
        """
        Wrapper for GET queries
        """
        try:
            r = requests.get(
                url,
                headers={"User-Agent": "urlhaus-harpoon"},
                data=query,
            )
            if r.ok:
                try:
                    open(query, "wb").write(r.content)
                    print("File saved to " + query)
                    return True
                except Exception as e:
                    raise UrlHausError()
            else:
                print("File not found")
        except Exception as e:
            raise UrlHausError()

    def get_url(self, query):
        """
        Retrieve information about a given URL
        """

        url = "{}url/".format(self.base_url)
        print(self.launch_post_query(url, "url", query))

    def get_host(self, query):
        """
        Retrieve information about a given host
        """

        url = "{}host/".format(self.base_url)
        print(self.launch_post_query(url, "host", query))

    def get_payload(self, query):
        """
        Retrieve information about a md5 or sh256 payload
        """

        # check if the hash is md5 or sha256
        md5 = re.findall(r"([a-fA-F\d]{32})", query)
        sha256 = re.findall(r"\b[A-Fa-f0-9]{64}\b", query)
        url = "{}payload/".format(self.base_url)
        if len(md5) != 0 and len(sha256) == 0:
            print(self.launch_post_query(url, "md5_hash", query))
        elif len(md5) == 0 and len(sha256) != 0:
            print(self.launch_post_query(url, "sha256_hash", query))
        else:
            raise UrlHausError()

    def get_tag(self, query):
        """
        Retrieve information about a tag
        """

        url = "{}tag/".format(self.base_url)
        print(self.launch_post_query(url, "tag", query))

    def get_signature(self, query):
        """
        Retrieve information about a signature
        """

        url = "{}signature/".format(self.base_url)
        print(self.launch_post_query(url, "signature", query))

    def get_sample(self, query):
        """
        Retrieve a malware sample
        """

        url = "{}/download".format(self.base_url)
        self.download_sample(url, query)
