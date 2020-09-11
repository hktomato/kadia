# find_dispatchirp_func.py
import sys
import angr

arg_driverobject = 0xdead0000
arg_registrypath = 0xdead8000

MJ_DEVICE_CONTROL_OFFSET = 0xe0
MJ_CREATE_OFFSET = 0x70

class DriverAnalysis:
	def __init__(self, _driverpath):
		self.driverPath = _driverpath
		self.project = angr.Project(self.driverPath, load_options={'auto_load_libs': False})

		self.mj_create = 0
		self.mj_device_control = 0

	def set_mj_functions(self, state):
		self.mj_create = state.mem[arg_driverobject + MJ_CREATE_OFFSET].uint64_t.concrete
		self.mj_device_control = state.solver.eval(state.inspect.mem_write_expr)

	def find_mj_device_control(self):
		state = self.project.factory.entry_state()
		state.regs.rcx = arg_driverobject # arg1 - DriverObject
		state.regs.rdx = arg_registrypath # arg2 - RegistryPath

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
		print("Usage: %s driverPath" % sys.argv[0])
		sys.exit()

	driver = DriverAnalysis(sys.argv[1])
	mj_device_control_func = driver.find_mj_device_control()

	print("DispatchIRP function : 0x%x" % mj_device_control_func)
