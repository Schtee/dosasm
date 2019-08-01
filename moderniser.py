from reg16 import *
from capstone.x86_const import *

class Moderniser:
	def __init__(self, cfg):
		self.cfg = cfg

	def find_const_int21s(self):
		regs = Registers()
		regs.add_reg(Reg16(X86_REG_AX, X86_REG_AH, X86_REG_AL))
		regs.add_reg(Reg16(X86_REG_BX, X86_REG_BH, X86_REG_BL))
		regs.add_reg(Reg16(X86_REG_CX, X86_REG_CH, X86_REG_CL))
		regs.add_reg(Reg16(X86_REG_DX, X86_REG_DH, X86_REG_DL))

		for a in self.cfg.blocks:
			block = self.cfg.blocks[a]
			for i in block.insns:
				if i.id == X86_INS_MOV and len(i.operands) > 1 and i.operands[0].type == X86_OP_REG and i.operands[1].type == X86_OP_IMM:
					regs.set_val(i.operands[0].reg, i.operands[1].imm)
				else:
					for r in i.regs_write:
						regs.set_val(r, None)

				if i.id == X86_INS_INT and i.operands[0].value.imm == 0x21:
					ah = regs.get_val(X86_REG_AH)
					if ah == None:
						print('Got int 21 with unknown AX at %s' %hex(i.address))
					else:
						self.handle_int21(ah)

	def handle_int21(self, ah):
		# DOS version
		if ah == 0x30:
			# AL = major version number (00h if DOS 1.x)
			# AH = minor version number
			# BL:CX = 24-bit user serial number (most versions do not use this) if DOS <5 or AL=00h
			# BH = MS-DOS OEM number if DOS 5+ and AL=01h
			# BH = version flag bit 3: DOS is in ROM other: reserved (0)
			print('Should add set registers for dos version instructions')
