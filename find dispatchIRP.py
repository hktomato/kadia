# find_dispatchirp_func.py
import angr

find_flag = False

arg_driverobject = 0xdead0000
arg_registrypath = 0xdead8000

def breakfunc(state):
	global find_flag

	print('Addr :', state.inspect.mem_write_address)
	print('Expr :', state.inspect.mem_write_expr)
	
	find_flag = True

if __name__ == '__main__':
	project = angr.Project('./medcored.sys', load_options={'auto_load_libs': False})
	state = project.factory.entry_state()
	state.regs.rcx = arg_driverobject # arg1 - DriverObject
	state.regs.rdx = arg_registrypath # arg2 - RegistryPath

	simgr = project.factory.simgr(state)

	# Break on DispatchIRP's write
	state.inspect.b('mem_write',when=angr.BP_AFTER, mem_write_address=arg_driverobject+0xe0 ,action=breakfunc)

	# DFS
	simgr.use_technique(angr.exploration_techniques.dfs.DFS())
	simgr.run(until=lambda x: find_flag)