from capstone import *

class Disassembler:
	def __init__(self, code, offset):
		self.all_code = code
		self.offset = offset
		self.insns = {} # stored by original address
		self.labels = {} # stored by original address
		self.call_depth = 0

		self.md = Cs(CS_ARCH_X86, CS_MODE_16)
		self.md.detail = True
	
	def process_jump(self, i, call_depth):
		target = i.operands[0].value.imm
		self.disasm(target, call_depth)

	def process_call(self, i, call_depth):
		target = i.operands[0].value.imm
		self.disasm(target, call_depth + 1)

	def disasm(self, ip, call_depth = 0):
		code = self.all_code[ip - self.offset:]
		if ip in self.labels:
			return

		self.labels[ip] = 'label_%x' %(ip)

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
		target = i.operands[0].value.imm
		if not target in self.labels:
			print('No label for 0x%x' %(target))
		self.write_insn(i, '', f, self.labels[target])
		# self.write_insn(i, self.labels[target], f)

	def write(self, path):
		with open(path, 'w') as f:
			f.write('.intel_syntax noprefix\n')
			sorted_addresses = sorted(self.insns)
			for address in sorted_addresses:
				i = self.insns[address]
				label = self.labels[i.address] if i.address in self.labels else ''
				if CS_GRP_JUMP in i.groups:
					self.write_jump(i, label, f)
				elif CS_GRP_INT in i.groups:
					self.write_int(i, label, f)
				else:
					self.write_insn(i, label, f)
				#f.write('%s\t%s\t;0x%x\t%s\n' %(i.mnemonic, i.op_str, i.address, bytes))
