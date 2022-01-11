"""
DHT Bootstrap Router.

Usage: tinyBT.py [--ip=<ip>][-v | -vv | -vvv][--test]

Options:
  -h --help      Show this screen.
  --version      Show version.
  --ip=<ip>      ip address to use for router address.
  -v             set level of logging output (can be used multiple times).
  -t, --test     run quickie test
"""
from docopt import docopt
try:
    from tinyBT._version import __version__
except:
    from _version import __version__

parsed_args = {}

def parse(args=None):
    arguments = docopt(__doc__, argv=args, version=__version__)
    return arguments

if __name__ == '__main__':
    print(parse())
