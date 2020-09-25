import angr

#IOCTL_CODE_MODE = 'iocode'
CONSTRAINT_MODE = 'constraints'

class SwitchStateFinder(angr.ExplorationTechnique):
	def __init__(self, case):
		super(SwitchStateFinder, self).__init__()
		self._case = case
		self.switch_states = {}
		self.constraint_stashs = []

	def setup(self, simgr):
		if CONSTRAINT_MODE not in simgr.stashes:
			simgr.stashes[CONSTRAINT_MODE] = []

	def step(self, simgr, stash='active', **kwargs):
		simgr = simgr.step(stash=stash, **kwargs)

		if stash == 'active' and len(simgr.stashes[stash]) > 1:
			for state in simgr.stashes[stash]:
				try:
					io_code = state.solver.eval_one(self._case)
					
					if io_code in self.switch_states: # duplicated codes
						simgr.stashes[stash].remove(state)
						continue

					self.switch_states[io_code] = state
					simgr.stashes[stash].remove(state)
				except:
					pass

		return simgr

	def get_states(self):
		return self.switch_states

