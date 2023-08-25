from .circl import Circl
from .config import Config
from .help import Help
from .intel import Intel
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
]
