# find_dispatchirp_func.py
import sys
import angr
import archinfo

import structures
import explore_technique

MJ_DEVICE_CONTROL_OFFSET = 0xe0
MJ_CREATE_OFFSET = 0x70

arg_driverobject = 0xdead0000
arg_registrypath = 0xdead8000

arg_irp = 0xdeac0000
arg_iostacklocation = 0xdead8000

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
		super(WDMDriverAnalysis, self).__init__(*args, **kwargs)

		self.factory = WDMDriverFactory(self)
		self.project = self.factory.project

		self.mj_create = 0
		self.mj_device_control = 0

	
	def isWDM(self):
	        return True if self.project.loader.find_symbol('IoCreateDevice') else False

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
		state = self.project.factory.call_state(self.mj_device_control,
												arg_driverobject,
												arg_irp)
		simgr = self.project.factory.simgr(state)

		io_stack_location = structures.IO_STACK_LOCATION(state, arg_iostacklocation)
		irp = structures.IRP(state, arg_irp)

		state.solver.add(irp.fields['Tail.Overlay.CurrentStackLocation'] == io_stack_location.address)
		state.solver.add(irp.fields['IoStatus.Status'] == 0)
		state.solver.add(io_stack_location.fields['MajorFunction'] == 14)

		ioctl_code_finder = explore_technique.IoctlCodeFinder(io_stack_location)
		simgr.use_technique(ioctl_code_finder)
		simgr.run()

		ioctl_codes = ioctl_code_finder.get_codes()
		ioctl_codes.sort()
		
		return list(map(hex, ioctl_codes))