"""
TTN DHT_Router.

Usage: ttnrouter.py [--ip=<ip>]

Options:
  -h --help     Show this screen.
  --version     Show version.
  --ip=<ip>     ip address to use for router address. [default: 127.0.0.1]
"""
import sys
from docopt import docopt
try:
    from _version import __version__
except:
    from tinyBT._version import __version__

parsed_args = {}

def parse(args=None):
    arguments = docopt(__doc__, argv=args, version=__version__)
    parsed_args = arguments.copy()
    return arguments

if __name__ == '__main__':
    print(parse())
