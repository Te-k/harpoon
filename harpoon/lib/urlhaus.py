#! /usr/bin/env python3

import re

import requests


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
        self.ua = "Harpoon (https://github.com/Te-k/harpoon)"

    def _query(self, query):
        headers = ({"User-Agent": self.ua},)
        return requests.get(self.base_url + query, headers=headers)

    def launch_post_query(self, url, key, query):
        """
        Wrapper for POST queries
        """
        try:
            r = requests.post(
                url,
                headers={"User-Agent": self.ua},
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
                headers={"User-Agent": self.ua},
                data=query,
            )
            if r.ok:
                try:
                    return r.content
                except:
                    raise UrlHausError()
            else:
                return None
        except Exception as e:
            raise UrlHausError(e)

    def get_url(self, query):
        """
        Retrieve information about a given URL
        """
        url = "{}url/".format(self.base_url)
        return self.launch_post_query(url, "url", query)

    def get_host(self, query):
        """
        Retrieve information about a given host
        """

        url = "{}host/".format(self.base_url)
        return self.launch_post_query(url, "host", query)

    def get_payload(self, query):
        """
        Retrieve information about a md5 or sh256 payload
        """
        url = "{}payload/".format(self.base_url)
        # check if the hash is md5 or sha256
        if re.match("[A-Fa-f0-9]{64}", query.strip()):
            return self.launch_post_query(url, "sha256_hash", query.strip())
        elif re.match("[a-fA-F\d]{32}", query.strip()):
            return self.launch_post_query(url, "md5_hash", query.strip())
        else:
            raise UrlHausError()

    def get_tag(self, query):
        """
        Retrieve information about a tag
        """
        url = "{}tag/".format(self.base_url)
        return self.launch_post_query(url, "tag", query)

    def get_signature(self, query):
        """
        Retrieve information about a signature
        """
        url = "{}signature/".format(self.base_url)
        return self.launch_post_query(url, "signature", query)

    def get_sample(self, query):
        """
        Retrieve a malware sample
        """
        url = "{}/download".format(self.base_url)
        return self.download_sample(url, query)
