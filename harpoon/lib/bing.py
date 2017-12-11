import requests
from bs4 import BeautifulSoup
from urllib.parse import urlencode
from dateutil.parser import parse
from harpoon.lib.utils import same_url

class Bing(object):
    @staticmethod
    def search(query):
        """
        Search in bing
        """
        # FIXME : change default UA
        r = requests.get(
            "https://www.bing.com/search",
            params = {'q': query }
        )
        soup = BeautifulSoup(r.text, 'lxml')
        res = []
        divs = soup.find_all('li', class_='b_algo')
        for d in divs:
            data = {
                'name': d.a.text,
                'url': d.a['href'],
                'text': d.p.text
            }
            attribution = d.find('div', class_='b_attribution')
            # Check if cache infos in attribute
            if 'u' in attribution.attrs:
                b = attribution['u'].split('|')
                data['cache'] = "http://cc.bingj.com/cache.aspx?d=%s&w=%s" % (
                    b[2],
                    b[3]
                )
            res.append(data)
        return res

    @staticmethod
    def download_cache(url):
        """
        Download cache data from a cached page
        """
        r = requests.get(url)
        if r.status_code == 200:
            if "Could not find the requested document in the cache" in r.text:
                # Bing bug
                return {"success": False}
            else:
                soup = BeautifulSoup(r.text, 'lxml')
                content = soup.find('div', class_='cacheContent')
                data = r.text[r.text.find('<div class="cacheContent">')+26:len(r.text)-41]
                return {
                    "success": True,
                    "date": parse(soup.find_all('strong')[1].text),
                    "data": str(content)[26:-40],
                    'url': soup.strong.a['href'],
                    'cacheurl': url
                }
        else:
            if r.status_code != 404:
                print('Weird, it should return 200 or 404')
            return {"success": False}

    @staticmethod
    def cache(url):
        """
        Search for an url in Bing cache
        """
        res = Bing.search(url)
        for i in res:
            if same_url(url, i['url']):
                if 'cache' in i:
                    return Bing.download_cache(i['cache'])
        return {'success': False}

