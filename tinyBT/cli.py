"""
TTN DHT_Router.

Usage: ttnrouter.py [--ip=127.0.0.1]

Options:
  -h --help     Show this screen.
  --version     Show version.
  --ip=<ip>     ip address to use for router address. [default: 127.0.0.1]
"""

import os, sys
sys.path.append(os.getcwd() + '/tinyBT')

from _version import __version__

parsed_args = {}

from docopt import docopt

def parse(args={}):
    arguments = docopt(__doc__, argv=args, version=__version__)
    parsed_args = arguments.copy()
    return arguments

if __name__ == '__main__':
    print(parse(['--version']))
