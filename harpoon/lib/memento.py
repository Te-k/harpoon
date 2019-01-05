import requests
import re
from urllib.parse import urljoin, quote
from dateutil.parser import parse

class MementoClient(object):
    """
    Implement Memento Protocol
    """
    def __init__(self, base_url='http://archive.is/'):
        self.base_url = base_url
        self.linkre = re.compile('^<(?P<url>[^>]+)>; rel="(?P<type>[a-z ]+)"(; datetime="(?P<date>[^"]+)"|,|; type="application/link-format"; from="(?P<from>[^"]+)"; until="(?P<until>[^"]+)")')

    def _parselinks(self, data):
        """
        Parse links from RFC 7089, returns list of links
        """
        res = []
        for d in data.split('\n'):
            if d != "":
                regex = self.linkre.match(d)
                if regex is not None:
                    new = {
                        'url': regex.group('url'),
                        'type': regex.group('type')
                    }
                    for i in ['from', 'until', 'date']:
                        if regex.group(i) is not None:
                            if i in regex.groupdict():
                                new[i] = parse(regex.group(i))
                    res.append(new)
        return res

    def snapshots(self, url):
        """
        Download list of snapshots for an url
        """
        r = requests.get(urljoin(self.base_url + 'timemap/', quote(url, safe='')), timeout=3)
        if r.status_code != 200:
            return []
        else:
            links = self._parselinks(r.text)
            # Get original url
            originals = list(
                filter(
                    lambda x: x['type'] == 'original',
                    links
                )
            )
            if len(originals) == 0:
                return []
            original = originals[0]['url']
            # Sort snapshots
            snapshots = []
            for d in links:
                if d['type'] in ['memento', 'first last memento']:
                    snapshots.append({
                        'url': original,
                        'date':d['date'],
                        'archive': d['url']
                    })
            return snapshots
