import urllib
from dateutil.parser import parse
import requests


class ArchiveOrg(object):
    """
    Object to download cache from archive.org
    """
    @staticmethod
    def snapshots(url):
        """
        Return a list of snapshots for a given url
        """
        # FIXME: report more snapshot through the Memento API
        r = requests.get('http://archive.org/wayback/available?url=%s' %
                urllib.parse.quote(url))
        data = r.json()
        res = []
        if 'archived_snapshots' in data:
            for i in data['archived_snapshots']:
                res.append({
                    'url': data['url'],
                    'archive': data['archived_snapshots'][i]['url'],
                    'date': parse(data['archived_snapshots'][i]['timestamp'])
                })
        return res

    @staticmethod
    def download_cache(cache_url):
        """
        Download cache from a cache url
        """
        if cache_url.startswith('https://web.archive.org/web/') or \
            cache_url.startswith('http://web.archive.org/web/'):
            r = requests.get(cache_url)
            data = r.text
            t1 = data.find('<!-- End Wayback Rewrite JS Include -->')
            cached_data = '<!doctype html>\n<html>\n<head>' + data[t1+39:]
            if cache_url.startswith('http://'):
                date = parse(cache_url[27:41])
            else:
                date = parse(cache_url[28:42])
            return {
                'success': True,
                'data': cached_data,
                'date': date,
                'cacheurl': cache_url
            }
        else:
            return {'success': False}

    @staticmethod
    def cache(url):
        """
        Download an url from a cache
        """
        snapshots = ArchiveOrg.snapshots(url)
        if len(snapshots):
            last = sorted(snapshots, key=lambda x: x['date'], reverse=True)[0]
            return ArchiveOrg.download_cache(last['archive'])
        else:
            return {'success': False}

    @staticmethod
    def capture(url):
        """
        Capture url in Web Archive
        """
        # Copied from https://github.com/motherboardgithub/mass_archive/blob/master/mass_archive.py
        res = requests.get("https://web.archive.org/save/%s" % url)
        if res.status_code == 200:
            result = res.headers['Content-Location']
            internet_archive_url = "https://web.archive.org%s" % result
            return internet_archive_url
        else:
            raise Exception("Capture failed")
