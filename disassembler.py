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

	def process_jump(self, i, call_depth):
		self.disasm_internal(i.operands[0].value.imm, i, call_depth)

	def process_call(self, i, call_depth):
		self.disasm_internal(i.operands[0].value.imm, i, call_depth + 1)

	def disasm(self, ip):
		self.gen = CFG.Generator()
		self.disasm_internal(ip, None)

		print(self.gen)
	
	def disasm_internal(self, ip, source_insn, call_depth = 0):
		#print('Visiting %s' %hex(ip))
		self.gen.add_edge(source_insn, ip)

		is_fallthrough = False
		last_insn = None
		was_call = False

		code = self.all_code[ip - self.offset:]

		for i in self.md.disasm(code, self.offset + ip - self.offset):
			if i.address in self.insns:
				return

			self.insns[i.address] = i

			if is_fallthrough:
				self.gen.add_edge(last_insn, i.address)
				is_fallthrough = False
			
			if CS_GRP_JUMP in i.groups:
				self.process_jump(i, call_depth)
				# code after unconditional is unreachable, so stop
				if i.mnemonic.lower() == 'jmp':
					return
				else:
					is_fallthrough = True

			elif CS_GRP_CALL in i.groups:
				was_call = True
				self.process_call(i, call_depth)

			elif CS_GRP_RET in i.groups:
				if call_depth == 0:
					print('returned with call stack depth 0 at 0x%x' %(i.address))
				return

			elif i.id in Disassembler.loops:
				self.process_jump(i, call_depth)

			last_insn = i
