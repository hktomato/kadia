import angr

class IoctlCodeFinder(angr.ExplorationTechnique):
	def __init__(self, io_stack_location):
		super(IoctlCodeFinder, self).__init__()
		self.io_stack_location = io_stack_location
		self.ioctl_codes = []

	def step(self, simgr, stash='active', **kwargs):
		simgr = simgr.step(stash=stash, **kwargs)
		if len(simgr.stashes[stash]) > 1:
			for state in simgr.stashes[stash]:
				try:
					io_code = state.solver.eval_one(self.io_stack_location.fields['IoControlCode'])
					if io_code in self.ioctl_codes: # duplicated codes
						simgr.stashes[stash].remove(state)
						continue
					
					self.ioctl_codes.append(hex(io_code))
					simgr.stashes[stash].remove(state)
				except:
					pass
					
		return simgr

	def get_codes(self):
		return self.ioctl_codes
