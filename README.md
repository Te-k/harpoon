# Harpoon

OSINT / Threat Intel CLI tool.

# Install

## Requirements

As a pre-requesite for Harpoon, you need to install [lxml](https://lxml.de/installation.html) requirements, on Debian/Ubuntu : `sudo apt-get install libxml2-dev libxslt-dev python-dev`.

You need to have [geoipupdate](https://github.com/maxmind/geoipupdate) installed and [correctly configured](https://dev.maxmind.com/geoip/geoipupdate/) to use geolocation correctly (make sure you to have `GeoLite2-Country GeoLite2-City GeoLite2-ASN` as `EditionIDs`).

If you want to use the screenshot plugin, you need phantomjs and npm installed:

```
npm install -g phantomjs
```

## Installing harpoon

You can simply install the package from [pypi](https://pypi.org/project/harpoon/) with `pip install harpoon`

If the above install instructions didn't work, you can build the tool from source by executing the following commands in the terminal (this assumes you are using virtualenvs):

```
git clone https://github.com/Te-k/harpoon.git
cd harpoon
pip3 install .
```

## Configuration

To configure harpoon, run `harpoon config` and fill in the needed API keys.

Then run `harpoon config -u` to download needed files. Check what plugins are configured with `harpoon config -c`.

# Usage

After configuration the following plugins are available within the `harpoon` command:

```
asn                 Gather information on an ASN
binaryedge          Request BinaryEdge API
bitly               Request bit.ly information through the API
cache               Requests webpage cache from different sources
censys              Request information from Censys database (https://censys.io/)
certspotter         Get certificates from https://sslmate.com/certspotter
circl               Request the CIRCL passive DNS database
config              Configure Harpoon
crtsh               Search in https://crt.sh/ (Certificate Transparency database)
cybercure           Check if intelligence on an IP exists in cybercure.ai
dns                 Map DNS information for a domain or an IP
dnsdb               Requests Farsight DNSDB
fullcontact         Requests Full Contact API (https://www.fullcontact.com/)
github              Request Github information through the API
googl               Requests Google url shortener API
greynoise           Request Grey Noise API
help                Give help on an Harpoon command
hibp                Request Have I Been Pwned API (https://haveibeenpwned.com/)
hunter              Request hunter.io information through the API
hybrid              Requests Hybrid Analysis platform
ip                  Gather information on an IP address
ipinfo              Request ipinfo.io information
malshare            Requests MalShare database
misp                Get information from a MISP server through the API
opencage            Forward/Reverse geocoding using OpenCage Geocoder API
otx                 Requests information from AlienVault OTX
permacc             Request Perma.cc information through the API
pgp                 Search for information in PGP key servers
pt                  Requests Passive Total database
quad9               Check if a domain is blocked by Quad9
robtex              Search in Robtex API (https://www.robtex.com/api/)
safebrowsing        Check if the given domain is in Google safe Browsing list
save                Save a webpage in cache platforms
screenshot          Takes a screenshot of a webpage
shodan              Requests Shodan API
spyonweb            Search in SpyOnWeb through the API
telegram            Request information from Telegram through the API
threatgrid          Request Threat Grid API
totalhash           Request Total Hash API
twitter             Requests Twitter API
urlscan             Search and submit urls to urlscan.io
vt                  Request Virus Total API
```

You can get information on each command with `harpoon help COMMAND`

## Access Keys

* [AlienVault OTX](https://otx.alienvault.com/)
* [BinaryEdge](https://www.binaryedge.io/)
* [bit.ly](https://bitly.com/a/sign_up)
* [Censys](https://censys.io/register)
* [CertSpotter](https://sslmate.com/certspotter/pricing) : paid plans provide search in expired certificates (little interests imho, just use crtsh or censys). You don't need an account for actual certificates
* [CIRCL Passive DNS](https://www.circl.lu/services/passive-dns/)
* [Farsight Dnsdb](https://www.farsightsecurity.com/dnsdb-community-edition/)
* [FullContact](https://dashboard.fullcontact.com/register)
* [Have I Been Pwned](https://haveibeenpwned.com/)
* [Hunter](https://hunter.io/users/sign_up)
* [Hybrid Analysis](https://www.hybrid-analysis.com/apikeys/info)
* [ipinfo.io](https://ipinfo.io/)
* [MalShare](https://malshare.com/register.php)
* [MalShare](https://malshare.com/register.php)
* [OpenCage](https://opencagedata.com/)
* [PassiveTotal](https://community.riskiq.com/registration)
* [Permacc](https://perma.cc/)
* [Shodan](https://account.shodan.io/register)
* [SpyOnWeb](https://api.spyonweb.com/)
* Telegram : [Create an application](https://core.telegram.org/api/obtaining_api_id)
* [Total Hash](https://totalhash.cymru.com/contact-us/)
* [Twitter](https://developer.twitter.com/en/docs/ads/general/guides/getting-started)
* Virus Total : for public, create an account and get the API key in the [Settings page](https://www.virustotal.com/#/settings/apikey)

