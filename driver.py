import sys
import angr
import logging
import datetime
import boltons.timeutils

import winproject	
				
if __name__ == '__main__':
	start_time = datetime.datetime.utcnow()
	logging.getLogger('angr').setLevel('FATAL')

	if len(sys.argv) <= 1:
		print("[!] Usage: %s driverPath" % sys.argv[0])
		sys.exit()

	driver = winproject.WDMDriverAnalysis(sys.argv[1])

	if not driver.isWDM():
		print("[!] '%s' is not a WDM driver." % sys.argv[1])
		sys.exit()
	
	device_name = driver.find_device_name()
	print("[+] Device Name : %s" % device_name)

	mj_device_control_func = driver.find_mj_device_control()
	print("[+] DispatchIRP function : 0x%x" % mj_device_control_func)

	ioctl_codes = driver.find_ioctl_codes()
	print("[+] IOCTL Control Code :", ioctl_codes)

	#nt_status = driver.find_ioctl_codes2()
	#print('[+] NT_STATUS address : ', nt_status)
	
	elapsed = boltons.timeutils.decimal_relative_time(start_time, datetime.datetime.utcnow())
	print("[*] completed in: {0:.1f} {1}".format(*elapsed))
