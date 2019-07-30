class CFG:
    def addresses_to_string(addresses):
        return ''.join('{:02x}\n'.format(x) if x != None else 'None' for x in addresses)

    class Generator:
        def __init__(self):
            self.edges = []
            self.boundaries = []

        def add_edge(self, source_insn, destination):
            if source_insn != None:
                end = source_insn.address + source_insn.size
                self.boundaries.append(end)
            if not destination in self.boundaries:
                self.boundaries.append(destination)
            self.edges.append(CFG.Edge(None if source_insn == None else source_insn.address, destination))

        def __str__(self):
            return 'Boundaries: %s' %CFG.addresses_to_string(self.boundaries)

    class Edge:
        def __init__(self, source, destination):
            self.source = source
            self.destination = destination

    class BasicBlock:
        def __init__(self, label, entry_point):
            self.label = label
            self.entry_point = entry_point
            self.exit_point = None
            self.destinations = []

        def add_destination(self, destination):
            self.destinations.push(destination)
    

    def __init__(self):
        self.basic_blocks = {} # stored by entry point
        self.entry_point = None

    def add_basic_block(self, block):
        self.basic_blocks.append(block)
