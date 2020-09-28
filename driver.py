import sys
import angr
import logging
import argparse
import datetime
import boltons.timeutils

import winproject	
		
def setup_logging(args):
	level = getattr(logging, args.loglvl)
	logging.getLogger('angr').setLevel(level)
				
if __name__ == '__main__':
	start_time = datetime.datetime.utcnow()
	parser = argparse.ArgumentParser(description='Automatic Driver Analysis', usage='driver.py [-d] [driverPath] [-L] [logLevel] [-s]')
	parser.add_argument('-d', '--driver', dest='driver', help='driverPath')
	parser.add_argument('-L', '--log', default='FATAL', dest='loglvl', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'FATAL'), help='set the logging level')
	parser.add_argument('-s', '--skip', dest='skip', action='store_true', help='skip the functions that do not need to be analyzed')
	args = parser.parse_args()
	
	setup_logging(args)

	if len(sys.argv) <= 1:
		print("usage: %s" % parser.usage)
		sys.exit()

	driver = winproject.WDMDriverAnalysis(args.driver, support_selfmodifying_code=True, allowed_call_mode=args.skip)

	if not driver.isWDM():
		print("[!] '%s' is not a WDM driver." % args.driver)
		sys.exit()
	
	device_name = driver.find_device_name()
	print("[+] Device Name : %s" % device_name)

	mj_device_control_func = driver.find_mj_device_control()
	print("[+] DispatchIRP function : 0x%x" % mj_device_control_func)

	ioctl_interface = driver.recovey_ioctl_interface()
	print("[+] IOCTL Interface :", ioctl_interface)	
	
	elapsed = boltons.timeutils.decimal_relative_time(start_time, datetime.datetime.utcnow())
	print("[*] completed in: {0:.1f} {1}".format(*elapsed))
