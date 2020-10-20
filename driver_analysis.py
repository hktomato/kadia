import sys
import angr
import json
import logging
import argparse
import datetime
import boltons.timeutils

import winproject	
		
def setup_logging(args):
	level = getattr(logging, args.loglvl)
	logging.getLogger('angr').setLevel(level)

def make_json(args_out):
	with open('./output.json','w', encoding='utf-8') as make_file:
		json.dump(ioctl_interface, make_file, indent="\t")
		# constraints max, min to json

if __name__ == '__main__':
	start_time = datetime.datetime.utcnow()
	parser = argparse.ArgumentParser(description='Automatic Driver Analysis', usage='driver_analysis.py [-d] [driverPath] [-L] [logLevel] [-s]')
	parser.add_argument('-d', '--driver', dest='driver', help='driverPath')
	parser.add_argument('-L', '--log', default='FATAL', dest='loglvl', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'FATAL'), help='set the logging level')
	parser.add_argument('-s', '--skip', dest='skip', action='store_true', help='skip the functions that do not need to be analyzed')
	parser.add_argument('-o', '--out', dest='out', action='store_true', help='output data to json file' )
	args = parser.parse_args()
	
	setup_logging(args)

	if len(sys.argv) <= 1:
		print("usage: %s" % parser.usage)
		sys.exit()

	driver = winproject.WDMDriverAnalysis(args.driver, skip_call_mode=args.skip)

	if driver.isWDM():
		device_name = driver.find_device_name()
		print("[+] Device Name : %s" % device_name)

		mj_device_control_func = driver.find_DispatchDeviceControl()
		print("[+] DispatchIRP function : 0x%x" % mj_device_control_func)

		ioctl_interface = driver.recovery_ioctl_interface()
		print("[+] IOCTL Interface :")
		print(json.dumps(ioctl_interface,indent="\t"))
		if (args.out):
			make_json(args.out)
		
		elapsed = boltons.timeutils.decimal_relative_time(start_time, datetime.datetime.utcnow())
		print("[*] completed in: {0:.1f} {1}".format(*elapsed))
	else:
		print("[!] '%s' is not a supperted driver." % args.driver)
		sys.exit()