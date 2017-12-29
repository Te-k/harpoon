import requests
import re
from bs4 import BeautifulSoup
from dateutil.parser import parse


class Pgp(object):
    @staticmethod
    def search(search):
        url = "http://pgp.mit.edu/pks/lookup?search=" + search
        r = requests.get(url)
        if "No results found" in r.text:
            # Nothing found
            return []
        res = []
        soup = BeautifulSoup(r.text, 'lxml')
        emailsearch = re.compile("([\w\(\) ]+) &lt;([\w@\.]+)&gt;")
        for pre in soup.find_all('pre')[1:]:
            key = {}
            t = str(pre)
            key['revoked'] = "*** KEY REVOKED ***" in t
            key['id'] = pre.a['href'][26:]
            a = t.find('</a>')
            key['date'] = parse(t[a+5:a+15])
            key['emails'] = []
            # get ready for regex
            for i in emailsearch.findall(t):
                key['emails'].append([i[0].strip(), i[1].strip()])

            res.append(key)
        return res
