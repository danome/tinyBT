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

log = logging.getLogger(__name__)

default_setup = {'check_t': 3, 'check_N': 5, 'report_t': 30, 'redeem_t': 1200,
		 'limit_t': 300, 'limit_N': 4, 'last_ping': 10, 'ping_timeout': 2}
	#{'discover_t': 180, 'check_t': 30, 'check_N': 10, 'cleanup_timeout': 60, 'cleanup_interval: 10}
	#{'report_t': 10, 'limit_t': 30, 'limit_N': 2000, 'redeem_t': 300, 'redeem_frac': 0.05


def set_log_levels(options):
    if '-v' in options:
        if options['-v'] == 0:
            klog_level = logging.INFO
            dlog_level = logging.INFO
        elif options['-v'] == 1:
            klog_level = logging.ERROR
            dlog_level = logging.ERROR
        elif options['-v'] == 2:
            klog_level = logging.WARNING
            dlog_level = logging.WARNING
        elif options['-v'] == 3:
            dlog_level = logging.INFO
            klog_level = logging.WARNING
        elif options['-v'] == 4:
            dlog_level = logging.DEBUG
            klog_level = logging.INFO
        else:
            klog_level = logging.DEBUG
            dlog_level = logging.DEBUG
    else:
        klog_level = logging.CRITICAL
        dlog_level = logging.CRITICAL
    logging.getLogger('cli').setLevel(dlog_level)
    logging.getLogger('dht').setLevel(dlog_level)
    logging.getLogger('krpc').setLevel(klog_level)
    logging.getLogger('util').setLevel(klog_level)
    logging.getLogger('DHT').setLevel(dlog_level)
    logging.getLogger('DHT_Router').setLevel(dlog_level)
    logging.getLogger('KRPCPeer').setLevel(klog_level)
    logging.getLogger('KRPCPeer.local').setLevel(klog_level)
    logging.getLogger('KRPCPeer.remote').setLevel(klog_level)

def main(vargs=None):
    options = parse(vargs)
    logging.basicConfig(handlers=[logging.FileHandler("/tmp/ttn-bootstrap.log"),
                                  logging.StreamHandler()],
                        format='[{asctime}]{levelname}:{name}({lineno}) > {message}',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.INFO,
                        style='{')
    set_log_levels(options)
    log.info(f'version: %s, options: %s' % (version.__version__, options))
    dht.init_dht(options)
    if options is not None and '--test' in options and options['--test'] is True:
        dht.test_dht(options, default_setup)
    else:
        dht.add_dht(dht.dht_id_root, options, default_setup)

if __name__ == '__main__':
    main()    # vargs=['-vvv', '--test']

