# Harpoon

OSINT tool.

## Plugins:

```
safebrowsing        Check if the given domain is in Google safe Browsing list
hibp                Request Have I Been Pwned API (https://haveibeenpwned.com/)
cache               Requests webpage cache from different sources
misp                Get information from a MISP server through the API
spyonweb            Search in SpyOnWeb through the API
censys              Request information from Censys database (https://censys.io/)
shodan              Requests Shodan API
vt                  Request Virus Total API
config              Configure Harpoon
fullcontact         Requests Full Contact API (https://www.fullcontact.com/)
googl               Requests Google url shortener API
ip                  Gather information on an IP address
twitter             Requests Twitter API
asn                 Gather information on an ASN
robtex              Search in Robtex API (https://www.robtex.com/api/)
hunter              Request hunter.io information through the API
otx                 Requests information from AlienVault OTX
crtsh               Search in https://crt.sh/ (Certificate Transparency database)
github              Request Github information through the API
bitly               Request bit.ly information through the API
screenshot          Takes a screenshot of a webpage
greynoise           Request Grey Noise API
telegram            Request information from Telegram through the API
```

To configure harpoon, run `harpoon config` and fil needed API keys. Then run `harpoon config -u` to download needed files. Check what plugins are configured with `harpoon config -c`.

## Access Keys

* Telegram : [Create an application](https://core.telegram.org/api/obtaining_api_id)
* Virus Total : for public, create an account and get the API key in the [Settings page](https://www.virustotal.com/#/settings/apikey)

## Install

For the screenshot plugin, you need phantomjs:
```
npm install -g phantomjs
```
