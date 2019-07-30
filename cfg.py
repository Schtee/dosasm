class CFG:
    def addresses_to_string(addresses):
        return ''.join('{:02x}\n'.format(x) if x != None else 'None' for x in addresses)

    class Generator:
        def __init__(self):
            self.edges = []
            self.boundaries = []

        def add_edge(self, source_insn, destination):
            if source_insn == None:
                self.entry_point = destination
            else:
                end = source_insn.address + source_insn.size
                self.boundaries.append(end)
            if not destination in self.boundaries:
                self.boundaries.append(destination)
            self.edges.append(CFG.Edge(None if source_insn == None else source_insn.address, destination))

        def generate(self, insns):
            addresses = sorted(insns)

            current_block = None

            blocks = []

            for a in addresses:
                i = insns[a]
                # current_block is None for first insn (i.e. first insn)
                if current_block == None or a in self.boundaries:
                    if a == self.entry_point:
                        label = 'start'
                    else:
                        label = 'label_%x' %a
                    current_block = CFG.BasicBlock(label)
                    blocks.append(current_block)

                current_block.insns.append(i)

            return CFG(blocks)

        def __str__(self):
            return 'Boundaries: %s' %CFG.addresses_to_string(self.boundaries)

    class Edge:
        def __init__(self, source, destination):
            self.source = source
            self.destination = destination

    class BasicBlock:
        def __init__(self, label):
            self.label = label
            self.insns = []

    def __init__(self, blocks):
        self.blocks = blocks
