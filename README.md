# Harpoon

OSINT tool.

# Install

You can simply pip install the tool:

```
pip install git+ssh://git@github.com/Te-k/harpoon  --process-dependency-links
```

Optionally if you want to use the screenshot plugin, you need phantomjs and npm installed:

```
npm install -g phantomjs
```

If the above install instructions didn't work, you can build the tool from source by executing the following commands in the terminal:

```
git clone https://github.com/Te-k/harpoon.git
cd harpoon
sudo pip3 install -r requirements.txt
sudo python3 setup.py install
```

To configure harpoon, run ```harpoon config``` and fill in the needed API keys. Then run ```harpoon config -u``` to download needed files. Check what plugins are configured with ```harpoon config -c```.

# Usage

After configuration the following plugins are available within the ```harpoon``` command:

```
help                Give help on an Harpoon command
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
threatgrid          Request Threat Grid API
pgp                 Search for information in PGP key servers
totalhash           Request Total Hash API
dns                 Map DNS information for a domain or an IP
hybrid              Requests Hybrid Analysis platform
malshare            Requests MalShare database
```

You can get information on each command with `harpoon help COMMAND`

## Access Keys

* Telegram : [Create an application](https://core.telegram.org/api/obtaining_api_id)
* Virus Total : for public, create an account and get the API key in the [Settings page](https://www.virustotal.com/#/settings/apikey)
* [Total Hash](https://totalhash.cymru.com/contact-us/)
* [Hybrid Analysis](https://www.hybrid-analysis.com/apikeys/info)
* [MalShare](https://malshare.com/register.php)
