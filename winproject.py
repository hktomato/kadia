import re
import sys
import angr
import claripy
import archinfo
from pprint import pprint as pp
import structures
import explore_technique
from capstone import *

MJ_DEVICE_CONTROL_OFFSET = 0xe0
MJ_CREATE_OFFSET = 0x70
arg_deviceobject = 0xdead9000
arg_driverobject = 0xdead0000
arg_registrypath = 0xdead8000
arg_irp = 0xdeac0000
arg_iostacklocation = 0xdead8000

def ast_repr(node):
		if not isinstance(node, claripy.ast.Base):
			raise TypeError('node must be an instance of claripy.ast.Base not: ' + repr(node))
		return re.sub(r'([^a-zA-Z][a-zA-Z]+)_\d+_\d+([^\d]|$)', r'\1\2', node.__repr__(inner=True))

class WDMDriverFactory(angr.factory.AngrObjectFactory):
	def __init__(self, *args, **kwargs):
		super(WDMDriverFactory, self).__init__(*args, **kwargs)

		# set the default calling convention
		if isinstance(self.project.arch, archinfo.ArchAMD64):
			self._default_cc = angr.calling_conventions.SimCCMicrosoftAMD64(self.project.arch)
		else:
			raise ValueError('Unsupported architecture')

	def call_state(self, addr, *args, **kwargs):
		# Todo : little endian and big endian confliction.
		#kwargs['add_options'] = kwargs.pop('add_options', angr.options.unicorn)
		cc = kwargs.pop('cc', self._default_cc)
		kwargs['cc'] = cc

		return super(WDMDriverFactory, self).call_state(addr, *args, **kwargs)

class WDMDriverAnalysis(angr.Project):
	def __init__(self, *args, **kwargs):
		kwargs['auto_load_libs'] = kwargs.pop('auto_load_libs', False)
		#kwargs['use_sim_procedures'] = kw++-------args.pop('use_sim_procedures', False)
		super(WDMDriverAnalysis, self).__init__(*args, **kwargs)

		self.factory = WDMDriverFactory(self)
		self.project = self.factory.project

		self.mj_create = 0
		self.mj_device_control = 0
		self.driver_path = args[0]

	
	def isWDM(self):
	        return True if self.project.loader.find_symbol('IoCreateDevice') else False

	def find_device_name(self):
		DOS_DEVICES = "\\DosDevices\\".encode('utf-16le')
		data = open(self.driver_path, 'rb').read()

		cursor = data.find(DOS_DEVICES)
		terminate = data.find(b'\x00\x00', cursor)

		if ( terminate - cursor) %2:
		    terminate +=1
		match = data[cursor:terminate].decode('utf-16le')
		return match

	def set_mj_functions(self, state):
		self.mj_create = state.mem[arg_driverobject + MJ_CREATE_OFFSET].uint64_t.concrete
		self.mj_device_control = state.solver.eval(state.inspect.mem_write_expr)

	def find_mj_device_control(self):
		state = self.project.factory.call_state(self.project.entry, arg_driverobject, arg_registrypath)
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

	def find_ioctl_codes(self):
		state = self.project.factory.call_state(self.mj_device_control, arg_driverobject, arg_irp)
		simgr = self.project.factory.simgr(state)
		
		cfg = self.project.analyses.CFGFast(function_starts=(self.mj_device_control,), normalize=True)
		
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
		#print('[+] NT_STATUS address : ', nt_status)
		nt_status.sort()
		
		#print(nt_status)
		
		io_stack_location = structures.IO_STACK_LOCATION(state, arg_iostacklocation)
		irp = structures.IRP(state, arg_irp)

		state.solver.add(irp.fields['Tail.Overlay.CurrentStackLocation'] == io_stack_location.address)
		state.solver.add(irp.fields['IoStatus.Status'] == 0)
		state.solver.add(io_stack_location.fields['MajorFunction'] == 14)

		ioctl_code_finder = explore_technique.IoctlCodeFinder(io_stack_location)
		simgr.use_technique(ioctl_code_finder)
		simgr.run()
		simgr.stashes['deadended'] = []
				
		for i in range(10): 
			#import ipdb; ipdb.set_trace()
					
			simgr.step(stash='constraints')
			for s in simgr.stashes['constraints']:
				if s.addr in nt_status:
					simgr.stashes['constraints'].remove(s)

		constraints_list = []
		ret = []

		simgr.move(from_stash = 'deadended', to_stash = 'constraints')
		
		#import ipdb; ipdb.set_trace()
		print(len(simgr.stashes['deadended']), len(simgr.stashes['constraints']))		
		
		for state in simgr.stashes['constraints']:
			#import ipdb; ipdb.set_trace()
			for constraint in state.solver.constraints:				
				con = ast_repr(constraint)
				if 'InputBufferLength' in con:
					constraints_list.append(con)
				elif 'OutputBufferLength' in con:
					constraints_list.append(con)
						
			value = {
				'IoControlCode': state.solver.eval(io_stack_location.fields['IoControlCode']),
				'constraints': set(constraints_list)
			}
			pp(value)
			constraints_list = []
			#ret.append(value)	
		
		return ret
