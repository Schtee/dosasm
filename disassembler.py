from capstone import *
from capstone.x86_const import *
from enum import IntEnum
from cfg import *

class Disassembler:
	class TargetBits(IntEnum):
		x32 = 32
		x64 = 64

	entry_point_label = '_start'
	loops = [ X86_INS_LOOP, X86_INS_LOOPE, X86_INS_LOOPNE ]

	def __init__(self, code, offset, exe_file, header, bits):
		self.all_code = code
		self.offset = offset
		self.insns = {} # stored by original address
		self.labels = {} # stored by original address
		self.call_depth = 0
		self.entry_point = None
		self.exe_file = exe_file
		self.header = header
		self.bits = bits

		self.md = Cs(CS_ARCH_X86, CS_MODE_16)
		self.md.detail = True

	def process_jump(self, i, gen, call_depth):
		self.disasm_internal(i.operands[0].value.imm, i, gen, call_depth)

	def process_call(self, i, gen, call_depth):
		self.disasm_internal(i.operands[0].value.imm, i, gen, call_depth + 1)

	def disasm(self, ip):
		gen = CFG.Generator()
		self.disasm_internal(ip, None, gen)

		self.cfg = gen.generate(self.insns)

		self.find_const_int21s()

	def find_const_int21s(self):
		for a in self.cfg.blocks:
			block = self.cfg.blocks[a]
			last_ah_val = None
			for i in block.insns:
				if i.id == X86_INS_MOV and i.reg_write(X86_REG_AH) and i.operands[0].value.imm:
					print("0x%x modifies ah" %i.address)

				if i.id == X86_INS_INT and i.operands[0].value.imm == 0x21:
					print('Found int 21...')
	
	def disasm_internal(self, ip, source_insn, gen, call_depth = 0):
		#print('Visiting %s' %hex(ip))
		gen.add_edge(source_insn, ip)

		is_fallthrough = False
		last_insn = None
		was_call = False

		code = self.all_code[ip - self.offset:]

		for i in self.md.disasm(code, self.offset + ip - self.offset):
			if i.address in self.insns:
				return

			self.insns[i.address] = i

			if is_fallthrough:
				gen.add_edge(last_insn, i.address)
				is_fallthrough = False
			
			if CS_GRP_JUMP in i.groups:
				self.process_jump(i, gen, call_depth)
				# code after unconditional is unreachable, so stop
				if i.mnemonic.lower() == 'jmp':
					return
				else:
					is_fallthrough = True

			elif CS_GRP_CALL in i.groups:
				was_call = True
				self.process_call(i, gen, call_depth)

			elif CS_GRP_RET in i.groups:
				if call_depth == 0:
					print('returned with call stack depth 0 at 0x%x' %(i.address))
				return

			elif i.id in Disassembler.loops:
				self.process_jump(i, gen, call_depth)

			last_insn = i

	def write_line(f, mnemonic, op_str, address):
		f.write('\t%s %s # 0x%x\n' %(mnemonic, op_str, address))

	def should_label_op(i):
		return (CS_GRP_JUMP in i.groups or CS_GRP_CALL in i.groups or i.id in Disassembler.loops) and i.operands[0].type == X86_OP_IMM

	def get_op_str(self, i):
		if not Disassembler.should_label_op(i):
			return i.op_str
		target = i.operands[0].imm
		if target in self.cfg.blocks:
			return self.cfg.blocks[target].label
		else:
			raise Exception('No block starting at 0x%x' %target)

	def write(self, path):
		with open(path, 'w') as f:
			for entry in self.cfg.blocks:
				block = self.cfg.blocks[entry]
				f.write('%s:\n' %block.label)

				for i in block.insns:
					op_str = self.get_op_str(i)

					Disassembler.write_line(f, i.mnemonic, op_str, i.address)
