class Reg16:
	def __init__(self, reg_id, high_reg_id, low_reg_id):
		self.reg_id = reg_id
		self.high_reg_id = high_reg_id
		self.low_reg_id = low_reg_id
		self.high_val = 0
		self.low_val = 0

	@property
	def val(self):
		if self.high_val == None or self.low_val == None:
			return None
		return (self.high_val << 8) | self.low_val

	@val.setter
	def val(self, v):
		if v == None:
			self.high_val = None
			self.low_val = None
		else:
			self.high_val = v >> 8
			self.low_val = v & 0xFF

class Registers:
	def __init__(self):
		self.all_regs = {}
		self.full_regs = {}
		self.high_regs = {}
		self.low_regs = {}

	def add_reg(self, reg):
		self.all_regs[reg.reg_id] = reg
		self.full_regs[reg.reg_id] = reg
		self.high_regs[reg.high_reg_id] = reg
		self.low_regs[reg.low_reg_id] = reg

	def set_val(self, reg_id, val):
		if reg_id in self.full_regs:
			self.full_regs[reg_id].val = val
		elif reg_id in self.high_regs:
			self.high_regs[reg_id].high_val = val
		elif reg_id in self.low_regs:
			self.low_regs[reg_id].low_val = val
		else:
			reg = Reg16(reg_id, None, None)
			reg.value = val
			self.full_regs[reg_id] = reg
			self.all_regs[reg_id] = reg

	def get_val(self, reg_id):
		if reg_id in self.full_regs:
			return self.full_regs[reg_id].val
		elif reg_id in self.high_regs:
			return self.high_regs[reg_id].high_val
		elif reg_id in self.low_regs:
			return self.low_regs[reg_id].low_val
		if reg_id in self.all_regs:
			return self.all_regs[reg_id]
		else:
			raise Exception('No register %d' %reg_id)
