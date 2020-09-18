import angr

class IoctlCodeFinder(angr.ExplorationTechnique):
	def __init__(self, io_stack_location, deferred_stash='deferred'):
		super(IoctlCodeFinder, self).__init__()
		self.deferred_stash = deferred_stash
		self.io_stack_location = io_stack_location
		self.ioctl_codes = []

	def setup(self, simgr):
		if self.deferred_stash not in simgr.stashes:
			simgr.stashes[self.deferred_stash] = []

	def step(self, simgr, stash='active', **kwargs):
		simgr = simgr.step(stash=stash, **kwargs)
		if len(simgr.stashes[stash]) > 1:
			for state in simgr.stashes[stash]:
				try:
					io_code = state.solver.eval_one(self.io_stack_location.fields['IoControlCode'])
					if io_code in self.ioctl_codes: # duplicated codes
						simgr.stashes[stash].remove(state)
						continue
					
					self.ioctl_codes.append(io_code)
					simgr.stashes[stash].remove(state)
					break
				except:
					pass
					
		return simgr

	def get_codes(self):
		return self.ioctl_codes