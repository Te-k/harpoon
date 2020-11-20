import requests
import hmac
import hashlib
import xml.etree.ElementTree as ET
from dateutil.parser import parse


class TotalHashError(Exception):
    pass


class TotalHashNotFound(TotalHashError):
    pass


class TotalHash(object):
    """
    Total hash APi Wrapper
    Check https://totalhash.cymru.com/api-documentation/#code_examples
    """
    def __init__(self, user, key):
        self.user = user
        self.key = key
        self.base_url = "https://api.totalhash.com"

    def _query(self, query):
        return requests.get(self.base_url + query)

    def search(self, query):
        """
        Search for a search term (max 10 results)
        """
        # TODO: check that the query is valid
        sign = hmac.new(
            self.key.encode("utf-8"),
            query.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        res = self._query("/search/%s&id=%s&sign=%s" % (query, self.user, sign))
        if res.status_code != 200:
            raise TotalHashError()
        else:
            root = ET.fromstring(res.text)
            result = root.find('result')
            res = {
                'total': int(result.attrib['numFound']),
                'results': [a.text for a in root.findall('.//result/doc/')]
            }
            return res

    def search_all(self, query):
        """
        Return all the results for a query
        """
        sign = hmac.new(
            self.key.encode("utf-8"),
            query.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        start = 0
        end = False
        results = {}
        while not end:
            res = self._query("/search/%s&id=%s&sign=%s&start=%i" % (query, self.user, sign, start))
            if res.status_code != 200:
                raise TotalHashError()
            else:
                root = ET.fromstring(res.text)
                if start == 0:
                    result = root.find('result')
                    results = {
                        'total': int(result.attrib['numFound']),
                        'results': [a.text for a in root.findall('.//result/doc/')]
                    }
                    start += len(results['results'])
                    if start >= results['total']:
                        return results
                else:
                    docs = root.findall('.//result/doc/')
                    for a in docs:
                        results['results'].append(a.text)
                    start += len(docs)
                    if start >= results['total']:
                        return results

    def analysis(self, sha):
        """
        Return the analysis of a hash
        """
        sign = hmac.new(
            self.key.encode("utf-8"),
            sha.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        res = self._query("/analysis/%s&id=%s&sign=%s" % (sha, self.user, sign))
        if res.status_code != 200:
            if res.status_code == 404:
                raise TotalHashNotFound()
            else:
                raise TotalHashError()
        else:
            try:
                root = ET.fromstring(res.text)
            except ET.ParseError:
                raise TotalHashError()

            # May not be complete
            results = {
                'sha1': root.attrib['sha1'],
                'time': parse(root.attrib['time']),
                'url': 'https://totalhash.cymru.com/analysis/?%s' % root.attrib['sha1'],
                'sections': [],
                'detections': [],
                'running_processes': [],
                'calltree': [],
                'network': {'dns': [], 'flows': []},
                'imports': [],
                'processes': []
            }
            try:
                results["md5"] = root.attrib['md5']
            except KeyError:
                pass
            try:
                results['magic'] = root.findall('static/magic')[0].attrib['value']
            except IndexError:
                pass
            try:
                results['timestamp'] = parse(root.findall('static/timestamp')[0].attrib['value'])
            except IndexError:
                pass
            try:
                results['pehash'] = root.findall('static/pehash')[0].attrib['value']
            except IndexError:
                pass
            for s in root.findall('static/section'):
                results['sections'].append(s.attrib)
            for i in root.findall('static/imports'):
                results['imports'].append(i.attrib['dll'])
            for a in root.findall('static/av'):
                results['detections'].append(a.attrib)
            for a in root.findall('network-pcap/dns'):
                results['network']['dns'].append(a.attrib)
            for a in root.findall('network-pcap/flows'):
                results['network']['flows'].append(a.attrib)
            for a in root.findall('running_processes/running_process'):
                results['running_processes'].append(a.attrib)
            for a in root.findall('calltree/process_call'):
                results['calltree'].append(a.attrib)

            # Processes
            for p in root.findall('processes/process'):
                pinfo = {
                        'dll': [],
                        'file': [],
                        'process': [],
                        'registry': [],
                        'mutex': []
                }
                for a in p.attrib:
                    pinfo[a] = p.attrib[a]

                for dll in p.findall('dll_handling_section/load_dll'):
                    pinfo['dll'].append(dll.attrib)
                for f in p.findall('filesystem_section/create_file'):
                    pinfo['file'].append(f.attrib)
                for pp in p.findall('process_section/create_process'):
                    pinfo['process'].append(pp.attrib)

                for r in p.findall('registry_section/set_value'):
                    pinfo['registry'].append(r.attrib)
                for m in p.findall('mutex_section/create_mutex'):
                    pinfo['mutex'].append(m.attrib)
                results['processes'].append(pinfo)

            return results

    def usage(self):
        """
        Retrieve API usage limit and count
        """
        sign = hmac.new(
            self.key.encode("utf-8"),
            b'usage',
            hashlib.sha256
        ).hexdigest()
        res = self._query("/usage/id=%s&sign=%s" % (self.user, sign))
        if res.status_code != 200:
            raise TotalHashError()
        else:
            return res.text




