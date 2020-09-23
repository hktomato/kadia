import angr

#IOCTL_CODE_MODE = 'iocode'
CONSTRAINT_MODE = 'constraints'

class IoctlCodeFinder(angr.ExplorationTechnique):
    def __init__(self, io_stack_location):
        super(IoctlCodeFinder, self).__init__()
        self.io_stack_location = io_stack_location
        self.io_codes = []

    def setup(self, simgr):
        if CONSTRAINT_MODE not in simgr.stashes:
            simgr.stashes[CONSTRAINT_MODE] = []

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        if stash == 'active' and len(simgr.stashes[stash]) > 1:
            for state in simgr.stashes[stash]:
                try:
                    io_code = state.solver.eval_one(self.io_stack_location.fields['IoControlCode'])
                    simgr.stashes[stash].remove(state)
                    
                    if io_code not in self.io_codes:
                    	simgr.stashes[CONSTRAINT_MODE].append(state)
                    
                    io_codes.append(io_code)
                except:
                    pass
        
        return simgr
