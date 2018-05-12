import requests
import archiveis
from dateutil.parser import parse
from harpoon.lib.memento import MementoClient


class ArchiveIs(object):
    """
    Class to request achive.is website
    """
    @staticmethod
    def snapshots(url):
        """
        Return all the screenshot of an url
        """
        mc = MementoClient(base_url='http://archive.is/')
        return mc.snapshots(url)

    @staticmethod
    def download_cache(cache_url):
        """
        return cache data from an archive.is cached url
        """
        r = requests.get(cache_url)
        data = r.text
        t1 = data.find('\n\n\n\n\n\n')
        t2 = data.find('</div></div><!--[if !IE]><!--><div style="position:absolute;right:1028px;top:-14px;bottom:-2px">')
        #t3 = data.find('<input style="border:1px solid black;height:20px;margin:0 0 0 0;padding:0;width:500px" type="text" name="q"')
        #t4 = data[t3+115:].find('"')
        t5 = data.find('<meta property="article:modified_time" content="')
        cached_data = data[t1+6:t2]
        #original_url = data[t3+115:t3+115+t4]
        date = parse(data[t5+48:t5+68])
        return {
            'success': True,
            'date': date,
            'data': cached_data,
            'cacheurl': cache_url
        }

    @staticmethod
    def cache(url):
        """
        Get a cache url and download the last one
        """
        snapshots = ArchiveIs.snapshots(url)
        if len(snapshots) > 0:
            last = sorted(snapshots, key=lambda x: x['date'], reverse=True)[0]
            return ArchiveIs.download_cache(last['archive'])
        else:
            return {
                'success': False
            }

    @staticmethod
    def capture(url):
        """
        Capture an url in archive.is
        """
        # Easiest way to do it for now, archive.is API sucks
        # FIXME replace this lib
        return archiveis.capture(url)
