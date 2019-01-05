import requests
import html
from dateutil.parser import parse
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from harpoon.lib.utils import same_url

class Google(object):
    @staticmethod
    def download_cache(url):
        """
        Download cache from a cache url
        """
        r = requests.get(url)
        if r.status_code == 200:
            mark1 = r.text.find("It is a snapshot of the page as it appeared on ")
            timestamptext = r.text[mark1+47:mark1+47+24]
            timestamp = parse(timestamptext)
            return {
                    "success": True,
                    "date": timestamp,
                    "data": html.unescape(r.text[r.text.find("<pre>")+5:r.text.find("</pre>")]),
                    'cacheurl': r.url

            }
        else:
            if r.status_code != 404:
                print("Weird, it should return 404...")
            return {"success": False}

    @staticmethod
    def search(query, num=10):
        payload = {
            "q": query,
            "num": num

        }
        r = requests.get(
            "https://www.google.com/search",
            params=payload
        )
        soup = BeautifulSoup(r.text, 'lxml')
        res = []
        divs = soup.find_all('div', class_='g')
        for d in divs:
            if d.h3:
                data = {
                    'name': d.h3.a.text
                }
                link = parse_qs(urlparse(d.h3.a['href']).query)
                if 'q' in link:
                    data['url'] = link['q'][0]
                else:
                    # Abnormal link (for instance Google books)
                    data['url'] = d.h3.a['href']
                text = d.find('span', class_='st')
                if text is not None:
                    data['text'] = text.text
                if d.ul:
                    for i in d.ul.children:
                        l = parse_qs(urlparse(i.a['href']).query)
                        if 'webcache.googleusercontent.com' in l['q'][0]:
                            data['cache'] = l['q'][0]
                res.append(data)
        return res

    @staticmethod
    def cache(url):
        payload = {
                "q": "cache:" + url,
                "num": 1,
                "strip":0,
                "vwsrc":1
        }
        r = requests.get(
            "https://webcache.googleusercontent.com/search",
            params=payload
        )
        if r.status_code == 200:
            # Copy code here to avoid doing another request
            mark1 = r.text.find("It is a snapshot of the page as it appeared on ")
            if mark1 > 0:
                timestamptext = r.text[mark1+47:mark1+47+24]
                timestamp = parse(timestamptext)
            if mark1 > 0:
                return {
                        "success": True,
                        "date": timestamp,
                        "data": html.unescape(r.text[r.text.find("<pre>")+5:r.text.find("</pre>")]),
                        'cacheurl': r.url,
                        'url': url
                }
            else:
                return {
                        "success": True,
                        "data": html.unescape(r.text[r.text.find("<pre>")+5:r.text.find("</pre>")]),
                        'cacheurl': r.url,
                        'url': url
                }
        else:
            # If not in cache directly, search on google for the cached url
            # Weirdly google does not find well url starting with a scheme
            if url.startswith('http://'):
                url = url[7:]
            elif url.startswith('https://'):
                url = url[8:]
            res = Google.search(url)
            for r in res:
                if same_url(url, r['url']) and 'cache' in r:
                    return Google.download_cache(r['cache'])
            return { 'success': False }
