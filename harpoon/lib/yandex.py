import requests
import urllib
from bs4 import BeautifulSoup
from harpoon.lib.utils import same_url

class Yandex(object):
    @staticmethod
    def search(req):
        '''
        Search for a request in Yandex and return results
        '''
        r = requests.get('https://yandex.ru/search/?text=%s' %
                urllib.parse.quote(req, safe='')
        )
        soup = BeautifulSoup(r.text, 'lxml')
        res = []
        for l in soup.find_all('li', class_='serp-item'):
            url = l.a['href']
            encoded_url = urllib.parse.quote(url, safe='')
            result = {
                'url': l.a['href'],
                'name': l.a.text,
            }
            text = l.find('div', class_="text-container")
            if(text):
                result['text'] = text.text
            popup = l.find_all('div', class_='popup2')
            if len(popup):
                for link in popup[0].find_all('a'):
                    if 'translate.yandex.ru' in link['href']:
                        if link['href'].startswith('http'):
                            result['translate'] = link['href']
                        else:
                            result['translate'] = 'http:' + link['href']
                    if 'hghltd.yandex.net' in link['href']:
                        result['cache'] = link['href']
            res.append(result)

        return res

    @staticmethod
    def download_cache(cache_url):
        '''
        Extract content from a cached Yandex url
        '''
        # FIXME: do not get date and url
        r = requests.get(cache_url)
        if r.status_code == 200:
            return {
                'success': True,
                'data': r.text[:-90],
                'cacheurl': cache_url,
            }
        else:
            return {'success': False}

    @staticmethod
    def cache(url):
        """
        Search for a cache url in yandex and if found get its content
        """
        # FIXME: miss obvious pages, like www.domain.com instead of domain.com
        res = Yandex.search(url)
        for i in res:
            if i['url'] == url:
                if 'cache' in i:
                    return Yandex.download_cache(i['cache'])
        return {'success': False }
