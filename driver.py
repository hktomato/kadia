import sys
import angr

import winproject
import logging

if __name__ == '__main__':
	logging.getLogger('angr').setLevel('NOTSET')

	if len(sys.argv) <= 1:
		print("[!] Usage: %s driverPath" % sys.argv[0])
		sys.exit()

	driver = winproject.WDMDriverAnalysis(sys.argv[1])

	if not driver.isWDM():
		print("[!] '%s' is not a WDM driver." % sys.argv[1])
		sys.exit()

	mj_device_control_func = driver.find_mj_device_control()
	print("[+] DispatchIRP function : 0x%x" % mj_device_control_func)

	ioctl_codes = driver.find_ioctl_codes()
	print("[+] IOCTL Control Code :", ioctl_codes)
	