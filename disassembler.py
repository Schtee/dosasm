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
		self.disasm_internal(i.operands[0].value.imm, i.address, call_depth)

	def process_call(self, i, call_depth):
		self.disasm_internal(i.operands[0].value.imm, i.address, call_depth + 1)

	def disasm(self, ip):
		self.boundaries = CFG.Boundaries()
		self.disasm_internal(ip, None)

		print(self.boundaries)
	
	def disasm_internal(self, ip, source, call_depth = 0):
		self.boundaries.add_edge(source, ip)

		is_fallthrough = False
		was_call = False

		code = self.all_code[ip - self.offset:]

		for i in self.md.disasm(code, self.offset + ip - self.offset):
			if i.address in self.insns:
				return

			self.insns[i.address] = i

			if is_fallthrough:
				self.boundaries.add_edge(last_address, i.address)
			
			if CS_GRP_JUMP in i.groups:
				self.process_jump(i, call_depth)
				# code after unconditional is unreachable, so stop
				if i.mnemonic.lower == 'jmp':
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

			last_address = i.address
'''
	def process_jump(self, i, call_depth):
		target = i.operands[0].value.imm
		self.disasm(target, call_depth)

	def process_call(self, i, call_depth):
		target = i.operands[0].value.imm
		self.disasm(target, call_depth + 1)

	def process_loop(self, i, call_depth):
		target = i.operands[0].value.imm
		self.disasm(target, call_depth)

	def disasm(self, ip, call_depth = 0):
		
		if ip in self.labels:
			return

		if self.entry_point == None:
			self.entry_point = ip
			label = Disassembler.entry_point_label
		else:
			label = 'label_%x' %ip

		self.labels[ip] = label

		code = self.all_code[ip - self.offset:]

		for i in self.md.disasm(code, self.offset + ip - self.offset):
			if i.address in self.insns:
				return
			self.insns[i.address] = i
			if CS_GRP_JUMP in i.groups:
				self.process_jump(i, call_depth)
				# if it's an unconditional jump, return as code below will be unreachable
				if i.mnemonic.lower() == 'jmp':
					return
			elif CS_GRP_CALL in i.groups:
				self.process_call(i, call_depth)
			elif CS_GRP_RET in i.groups:
				if call_depth == 0:
					print('returned with call stack depth 0 at 0x%x' %(i.address))
				return
			elif i.id in Disassembler.loops:
				self.process_loop(i, call_depth)

	def write_asm(self, label, code, f):
		out = '%s\t%s\n' %(label, code)
		f.write(out)

	def write_insn(self, i, label, f, op_override = None):
		bytes = ''.join('{:02x}'.format(x) for x in i.bytes)
		label = label if label == '' else label + ':'
		op_str = op_override if op_override != None else i.op_str
		out = '%s\t%s # 0x%x\t%s' %(i.mnemonic, op_str, i.address, bytes)
		self.write_asm(label, out, f)

	def write_int(self, i, label, f):
		f.write('# replacing %s %s\n' %(i.mnemonic, i.op_str))
		# Linux 64 calling convention = params in 64 bit gprs
		self.write_asm('', 'mov rdi, 0x%02x' %(i.operands[0].value.imm), f)
		self.write_asm('', 'movzx rsi, ax', f)
		self.write_asm('', 'call int_sim', f)

	def write_jump(self, i, label, f):
		target_label = None

		# if target is immediate, convert to label
		if i.operands[0].type == X86_OP_IMM:
			target = i.operands[0].value.imm
			if not target in self.labels:
				print('No label for 0x%x' %(target))
			target_label = self.labels[target]

		self.write_insn(i, label, f, target_label)

	def write_loop(self, i, label, f):
		target_label = None

		# if target is immediate, convert to label
		if i.operands[0].type == X86_OP_IMM:
			target = i.operands[0].value.imm
			if not target in self.labels:
				print('No label for 0x%x' %(target))
			target_label = self.labels[target]

		self.write_insn(i, label, f, target_label)

	def write_call(self, i, label, f):
		target_label = None

		# if target is immediate, convert to label
		if i.operands[0].type == X86_OP_IMM:
			target = i.operands[0].value.imm
			if not target in self.labels:
				print('No label for 0x%x' %(target))
			target_label = self.labels[target]

		self.write_insn(i, label, f, target_label)

	def write(self, path):

		with open(path, 'w') as f:
			f.write('.intel_syntax noprefix\n.include "int%s.s"\n.global %s\n' %(int(self.bits), Disassembler.entry_point_label))
			sorted_addresses = sorted(self.insns)

			for address in sorted_addresses:
				i = self.insns[address]
				label = self.labels[i.address] if i.address in self.labels else ''
				if CS_GRP_JUMP in i.groups:
					self.write_jump(i, label, f)
#elif CS_GRP_INT in i.groups:
#self.write_int(i, label, f)
				elif CS_GRP_CALL in i.groups:
					self.write_call(i, label, f)
				elif i.id in Disassembler.loops:
					self.write_loop(i, label, f)
				else:
					self.write_insn(i, label, f)
				#f.write('%s\t%s\t;0x%x\t%s\n' %(i.mnemonic, i.op_str, i.address, bytes))

#f.write('\n.section .data\nexe:\n.org %s\n.incbin "%s"' %(self.offset, self.exe_file))
				load_module_size = (self.header.file_pages * 512) + self.header.last_page_size - (self.header.header_paragraphs * 16)

			f.write('\n.section .data\npsp:\n.byte 00, 00\n.word 0x9FFF\n.org 0x100\n.global _exe\n_exe:\n.incbin "out.exe.stripped"\n.org %d\nss_sim: .word 0\nes_sim: .word 0\nds_sim: .word 0' %(load_module_size))
			'''
