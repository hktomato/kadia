import sys
import angr

import winproject
import structures

def _step_func(state):
	if state.solver.max(state.globals.io_stack_location.fields['IoControlCode']) == 1:
		print("aaaa")
	print("bbbb")

if __name__ == '__main__':
	if len(sys.argv) <= 1:
		print("[!] Usage: %s driverPath" % sys.argv[0])
		sys.exit()

	driver = winproject.WDMDriverAnalysis(sys.argv[1])

	if not driver.isWDM():
		print("[!] '%s' is not a WDM driver." % sys.argv[1])
		sys.exit()

	mj_device_control_func = driver.find_mj_device_control()
	print("[+] DispatchIRP function : 0x%x" % mj_device_control_func)
