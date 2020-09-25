import re
import sys
import angr
import claripy
import archinfo
from capstone import *

import structures
import explore_technique
from static_analysis import FunctionAnalysis

MJ_DEVICE_CONTROL_OFFSET = 0xe0
MJ_CREATE_OFFSET = 0x70

arg_deviceobject = 0xdead0000
arg_driverobject = 0xdead1000
arg_registrypath = 0xdead2000

arg_irp = 0xdead3000
arg_iostacklocation = 0xdead4000

import ipdb

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
		#kwargs['use_sim_procedures'] = kwargs.pop('use_sim_procedures', False)
		
		self.driver_path = args[0]
		self.func_analyzer = FunctionAnalysis(self.driver_path)
		self.allowed_call_mode = kwargs.pop('allowed_call_mode', False)

		super(WDMDriverAnalysis, self).__init__(*args, **kwargs)

		self.factory = WDMDriverFactory(self)
		self.project = self.factory.project

		self.mj_create = 0
		self.mj_device_control = 0

		self.constraints = []
	
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

	def allowed_call_technique(self, state):
		# Analyze prototype of the current function.
		func_prototypes = self.func_analyzer.prototype(state.addr)

		allowed = False
		for arg_type in func_prototypes:
			if '+' not in arg_type: 		# register
				argument = getattr(state.regs, arg_type)
			else:					# stack value
				offset = int(arg_type.split('+')[-1], 16)
				if 'rsp' in arg_type:
					argument = state.mem[state.regs.rsp + offset].uint64_t.resolved
				else:
					argument = state.mem[state.regs.rbp + offset].uint64_t.resolved

			if argument.symbolic:
				argument = str(argument)

				for arg in self.allowed_arguments:
					if isinstance(arg, str) and arg in argument:
						allowed = True
			else:
				argument = state.solver.eval(argument)

				if argument in self.allowed_arguments:
					allowed = True

			if allowed == True:
				break

		if not allowed:
			state.mem[state.regs.rip].uint8_t = 0xc3
			state.regs.rax = state.solver.BVS('ret', 64)


	def use_allowed_call_technique(self, state, arguments):
		self.allowed_arguments = arguments

		state.inspect.b('call', action=self.allowed_call_technique)

	def find_mj_device_control(self):
		state = self.project.factory.call_state(self.project.entry, arg_driverobject, arg_registrypath)
		if self.allowed_call_mode:
			self.use_allowed_call_technique(state, [arg_driverobject])

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

	def cond_read_systembuffer(self, state):
		return 'SystemBuffer' in str(state.inspect.mem_read_address)

	def cond_write_systembuffer(self, state):
		return 'SystemBuffer' in str(state.inspect.mem_write_address)

	def action_systembuffer(self, state):
		for constraint in state.solver.constraints:
			str_constraint = ast_repr(constraint)

			if 'InputBufferLength' in str_constraint or 'OutputBufferLength' in str_constraint:
				self.constraints.append(str_constraint)

	def recovey_ioctl_interface(self):
		state = self.project.factory.call_state(self.mj_device_control,
												arg_driverobject,
												arg_irp)
		# for medcored.sys (should be removed.)
		setattr(state.mem[0x10C5B8], 'uint64_t', state.solver.BVS('x', 64))

		if self.allowed_call_mode:
			self.use_allowed_call_technique(state, [arg_iostacklocation, 'IoControlCode', 'InputBuffer', 'CurrentStackLocation'])

		simgr = self.project.factory.simgr(state)

		io_stack_location = structures.IO_STACK_LOCATION(state, arg_iostacklocation)
		irp = structures.IRP(state, arg_irp)

		state.solver.add(irp.fields['Tail.Overlay.CurrentStackLocation'] == io_stack_location.address)
		state.solver.add(irp.fields['IoStatus.Status'] == 0)
		state.solver.add(io_stack_location.fields['MajorFunction'] == 14)

		state_finder = explore_technique.SwitchStateFinder(io_stack_location.fields['IoControlCode'])
		simgr.use_technique(state_finder)
		simgr.run()

		ioctl_interface = []
		switch_states = state_finder.get_states()
		for ioctl_code, state in switch_states.items():
			state.inspect.b('mem_read', condition=self.cond_read_systembuffer, action=self.action_systembuffer)
			state.inspect.b('mem_write', condition=self.cond_write_systembuffer, action=self.action_systembuffer)

			simgr = self.project.factory.simgr(state)
			simgr.run(until=lambda x: len(self.constraints))

			ioctl_interface.append({'code': ioctl_code, 'constraints':self.constraints})
			self.constraints = []

		return ioctl_interface