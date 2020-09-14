# find_dispatchirp_func.py
import sys
import angr
import archinfo

arg_driverobject = 0xdead0000
arg_registrypath = 0xdead8000

MJ_DEVICE_CONTROL_OFFSET = 0xe0
MJ_CREATE_OFFSET = 0x70

class WDMDriverAnalysis:
	def __init__(self, _driverpath):
		self.driverPath = _driverpath
		self.project = angr.Project(self.driverPath, load_options={'auto_load_libs': False})

		self.mj_create = 0
		self.mj_device_control = 0

		# set the default calling convention
		if isinstance(self.project.arch, archinfo.ArchAMD64):
			self._default_cc = angr.calling_conventions.SimCCMicrosoftAMD64(self.project.arch)
		else:
			raise ValueError('Unsupported architecture')

	def isWDM(self):
	        return True if self.project.loader.find_symbol('IoCreateDevice') else False

	def set_mj_functions(self, state):
		self.mj_create = state.mem[arg_driverobject + MJ_CREATE_OFFSET].uint64_t.concrete
		self.mj_device_control = state.solver.eval(state.inspect.mem_write_expr)

	def find_mj_device_control(self):
		state = self.project.factory.call_state(self.project.entry, arg_driverobject, arg_registrypath, cc=self._default_cc)

		simgr = self.project.factory.simgr(state)

		# Break on DriverObject->MajorFuntion[MJ_DEVICE_CONTROL]
		state.inspect.b('mem_write',when=angr.BP_AFTER,
		 				mem_write_address=arg_driverobject+MJ_DEVICE_CONTROL_OFFSET,
		 				action=self.set_mj_functions)

		# DFS exploration
		simgr.use_technique(angr.exploration_techniques.dfs.DFS())
		simgr.run(until=lambda x: self.mj_device_control)

		# Second exploration
		# to skip default mj function initialization.
		if self.mj_device_control == self.mj_create:
			for i in range(50):
				simgr.step()

				if self.mj_device_control != self.mj_create:
					break

		return self.mj_device_control

if __name__ == '__main__':
	if len(sys.argv) <= 1:
		print("[!] Usage: %s driverPath" % sys.argv[0])
		sys.exit()

	driver = WDMDriverAnalysis(sys.argv[1])

	if not driver.isWDM():
		print("[!] '%s' is not a WDM driver." % sys.argv[1])
		sys.exit()

	mj_device_control_func = driver.find_mj_device_control()

	print("[+] DispatchIRP function : 0x%x" % mj_device_control_func)
