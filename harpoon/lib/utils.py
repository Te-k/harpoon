import re
from IPy import IP
from urllib.parse import urlparse, parse_qs
from datetime import date, datetime

def unbracket(domain):
    """Remove protective bracket from a domain"""
    return domain.replace("[.]", ".")

def bracket(domain):
    """Add protective bracket to a domain"""
    last_dot = domain.rfind(".")
    return domain[:last_dot] + "[.]" + domain[last_dot+1:]

def json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError ("Type %s not serializable" % type(obj))

def same_url(url1, url2):
    """
    Check for minor differences between url1 and url2, return True if they are the same
    Currently only consider extra www. in domain, https/http and extra fragment
    """
    if url1 == url2:
        return True
    # Dirty hacks
    if not url1.startswith('http'):
        url1 = 'http://' + url1
    if not url2.startswith('http'):
        url2 = 'http://' + url2
    if not url1.endswith('/'):
        url1 += '/'
    if not url2.endswith('/'):
        url2 += '/'
    purl2 = urlparse(url2)
    purl1 = urlparse(url1)

    if purl1.path == purl2.path and purl1.params == purl2.params and \
            purl1.query == purl2.query:
        if purl1.netloc == purl2.netloc:
            return True
        else:
            if ("www." + purl1.netloc) == purl2.netloc:
                return True
            if ("www." + purl2.netloc) == purl1.netloc:
                return True
    return False

def typeguess(indicator):
    """
    Guess the type of the indicator
    returns string in "IPv4", "IPv6", "md5", "sha1", "sha256", "domain"
    """
    if re.match("^\w{32}$", indicator):
        return "md5"
    elif re.match("^\w{40}$", indicator):
        return "sha1"
    elif re.match("^\w{64}$", indicator):
        return "sha256"
    else:
        try:
            i = IP(indicator)
            if i.version() == 4:
                return "IPv4"
            else:
                return "IPv6"
        except ValueError:
            return "domain"

def is_ip(target):
    """
    Test if a string is an IP address
    """
    if isinstance(target, str):
        try:
            i = IP(target)
            return True
        except ValueError:
            return False
    else:
        return False
