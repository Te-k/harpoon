# Harpoon

OSINT tool.

# Install

First, you need to have development headers of python 3 installed, on ubuntu/debian just do `sudo apt install python3-dev`

Then, you can simply pip install the tool:

```
pip install git+https://github.com/Te-k/harpoon --process-dependency-links
```

Optionally if you want to use the screenshot plugin, you need phantomjs and npm installed:

```
npm install -g phantomjs
```

If the above install instructions didn't work, you can build the tool from source by executing the following commands in the terminal (this assumes you are using virtualenvs):

```
git clone https://github.com/Te-k/harpoon.git
cd harpoon
pip3 install -r requirements.txt
pip3 install .
```

To configure harpoon, run ```harpoon config``` and fill in the needed API keys. Then run ```harpoon config -u``` to download needed files. Check what plugins are configured with ```harpoon config -c```.

# Usage

After configuration the following plugins are available within the ```harpoon``` command:

```
asn                 Gather information on an ASN
bitly               Request bit.ly information through the API
cache               Requests webpage cache from different sources
censys              Request information from Censys database (https://censys.io/)
certspotter         Get certificates from https://sslmate.com/certspotter
config              Configure Harpoon
crtsh               Search in https://crt.sh/ (Certificate Transparency database)
cybercure           Check if intelligence on an IP exists in cybercure.ai
dns                 Map DNS information for a domain or an IP
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
vt                  Request Virus Total API
```

You can get information on each command with `harpoon help COMMAND`

## Access Keys

* [AlienVault OTX](https://otx.alienvault.com/)
* [bit.ly](https://bitly.com/a/sign_up)
* [Censys](https://censys.io/register)
* [CertSpotter](https://sslmate.com/certspotter/pricing) : paid plans provide search in expired certificates (little interests imho, just use crtsh or censys). You don't need an account for actual certificates
* [FullContact](https://dashboard.fullcontact.com/register)
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

