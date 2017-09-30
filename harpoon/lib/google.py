import requests
import html
from dateutil.parser import parse

class Google(object):
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
            mark1 = r.text.find("It is a snapshot of the page as it appeared on ")
            timestamptext = r.text[mark1+47:mark1+47+24]
            timestamp = parse(timestamptext)
            return {
                    "success": True,
                    "date": timestamptext,
                    "data": html.unescape(r.text[r.text.find("<pre>")+5:r.text.find("</pre>")]),
                    'url': r.url

            }
        else:
            if r.status_code != 404:
                print("Weird, it should return 404...")
            return {"success": False}
