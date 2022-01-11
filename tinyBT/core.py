import os, sys, time, socket, hashlib, hmac, threading, logging, random, inspect
import binascii
try:
    import tinyBT.dht	   as dht
    from   tinyBT.cli	   import parse
    import tinyBT._version as version
except:
    import dht	    as dht
    from   cli	    import parse
    import _version as version

logging.basicConfig(handlers=[logging.FileHandler("/tmp/ttn-bootstrap.log"),
			      logging.StreamHandler()],
		    format='[{asctime}]{levelname}:{message}',
		    datefmt='%Y-%m-%d %H:%M:%S',
		    level=logging.DEBUG,
		    style='{')

log = logging.getLogger(__name__)

default_setup = {'check_t': 3, 'check_N': 5, 'report_t': 30, 'redeem_t': 1200,
		 'limit_t': 300, 'limit_N': 4, 'last_ping': 10, 'ping_timeout': 2}
	#{'discover_t': 180, 'check_t': 30, 'check_N': 10, 'cleanup_timeout': 60, 'cleanup_interval: 10}
	#{'report_t': 10, 'limit_t': 30, 'limit_N': 2000, 'redeem_t': 300, 'redeem_frac': 0.05}

def main(test=False, vargs=None):
	options = parse(vargs)
	if '--test' in options:
		test = options['--test']
	log.info(f'bootstrap node, version: %s, options: %s' % (version.__version__, options))
	dht.init_dht(options)
	root=dht.add_dht(dht.dht_id_root, options, default_setup) # create root dht
	if test is True: dht.test_dht(options, default_setup)

if __name__ == '__main__':
	main(test=True, vargs=['-vvv', '--test'])
