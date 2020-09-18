import sys
import angr
import logging
from capstone import *

import winproject

DOS_DEVICES = "\\DosDevices\\".encode('utf-16le')

arg_driverobject = 0xdead0000
arg_registrypath = 0xdead8000
arg_deviceobject = 0xdeadc000
arg_irp = 0xdead1000

MJ_DEVICE_CONTROL_OFFSET = 0xe0
MJ_CREATE_OFFSET = 0x70

IO_STACK_LOCATION_OFFSET = 0xb8

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
            
	def find_device_name(self, path):
		f = open(path, 'rb')
		data = f.read()

		cursor = data.find(DOS_DEVICES)
		terminate = data.find(b'\x00\x00', cursor)

		if ( terminate - cursor) %2:
		    terminate +=1
		match = data[cursor:terminate].decode('utf-16le')
		f.close()
		return match

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
	
	def find_ioctl_state(self, mj_device_control):
		state = self.project.factory.call_state(mj_device_control, arg_deviceobject, arg_irp, cc=self._default_cc)

		simgr = self.project.factory.simgr(state)
		cfg = self.project.analyses.CFGFast(function_starts=(mj_device_control,), normalize=True)		
		#cfg = self.project.analyses.CFGEmulated(keep_state=False,max_iterations=5,normalize=True,starts=(mj_device_control,),)
		#print("This is the graph:", cfg.graph.nodes)
		
		nodes = cfg.nodes()
		node_list = list(nodes)
		md = Cs(CS_ARCH_X86, CS_MODE_64)

		nt_status = []
		node_cnt = 0
		for node in node_list:
			try:
				byte = node.block.bytes
				
			except:	
				del node_list[node_cnt]
				node_cnt += 1
			for i in md.disasm(byte, node.addr):
				#print(hex(i.address), i.mnemonic ,i.op_str)
				if i.mnemonic == 'mov' and '0xc00000' in i.op_str:
					nt_status.append(i.address)
		print('[+] NT_STATUS address : ', nt_status)
				
if __name__ == '__main__':
	logging.getLogger('angr').setLevel('NOTSET')

	if len(sys.argv) <= 1:
		print("[!] Usage: %s driverPath" % sys.argv[0])
		sys.exit()

	driver = winproject.WDMDriverAnalysis(sys.argv[1])

	if not driver.isWDM():
		print("[!] '%s' is not a WDM driver." % sys.argv[1])
		sys.exit()
	
	device_name = driver.find_device_name(sys.argv[1])
	print("[+] Device Name : %s" % device_name)

	mj_device_control_func = driver.find_mj_device_control()
	print("[+] DispatchIRP function : 0x%x" % mj_device_control_func)

	ioctl_codes = driver.find_ioctl_codes()
	print("[+] IOCTL Control Code :", ioctl_codes)
