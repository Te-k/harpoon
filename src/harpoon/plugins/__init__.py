from .circl import Circl
from .config import Config
from .help import Help
from .intel import Intel
from .ipinfo import IpInfo
from .shodan import Shodan
from .tor import Tor
from .urlscan import UrlScan
from .version import Version

PLUGINS = [
    Circl,
    Help,
    UrlScan,
    Version,
    Tor,
    Intel,
    Config,
    IpInfo,
    Shodan,
]
