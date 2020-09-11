# find_dispatchirp_func.py
import sys
import angr

arg_driverobject = 0xdead0000
arg_registrypath = 0xdead8000

class DriverAnalysis:
	def __init__(self, _driverpath):
		self.driverPath = _driverpath
		self.project = angr.Project(self.driverPath, load_options={'auto_load_libs': False})

		self.irp_func = 0

	def break_mem_write(self, state):
		self.irp_func = state.solver.eval(state.inspect.mem_write_expr)

	def find_irp_func(self):
		state = self.project.factory.entry_state()
		state.regs.rcx = arg_driverobject # arg1 - DriverObject
		state.regs.rdx = arg_registrypath # arg2 - RegistryPath

		simgr = self.project.factory.simgr(state)

		# Break on DispatchIRP's write
		state.inspect.b('mem_write',when=angr.BP_AFTER, mem_write_address=arg_driverobject+0xe0 ,action=self.break_mem_write)

		# DFS
		simgr.use_technique(angr.exploration_techniques.dfs.DFS())
		simgr.run(until=lambda x: self.irp_func)

		return self.irp_func

if __name__ == '__main__':
	if len(sys.argv) <= 1:
		print("Usage: %s driverPath" % sys.argv[0])
		sys.exit()

	driver = DriverAnalysis(sys.argv[1])
	irp_func = driver.find_irp_func()

	print("DispatchIRP function : 0x%x" % irp_func)
