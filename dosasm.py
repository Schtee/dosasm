import argparse

def read_word(f):
	import struct
	return struct.unpack('h', f.read(2))[0]

class DOSHeader:
	def __init__(self, f):
		self.signature = f.read(2)
		if not self.is_mz():
			return

		self.last_page_size = read_word(f)
		self.file_pages = read_word(f)
		self.relocation_item_count = read_word(f)
		self.header_paragraphs = read_word(f)
		self.minalloc = read_word(f)
		self.maxalloc = read_word(f)
		self.initial_ss_value = read_word(f)
		self.initial_sp_value = read_word(f)
		self.checksum = read_word(f)
		self.initial_ip_value = read_word(f)
		self.initial_cs_value = read_word(f) # this is pre-relocation
		self.relocation_table_offset = read_word(f)
		self.overlay_number = read_word(f)
		self.relocation_table = []
		f.seek(self.relocation_table_offset)
		for i in range(0, self.relocation_item_count):
			self.relocation_table.append({ 'offset': read_word(f), 'segment_address': read_word(f) })

	def is_mz(self):
		return self.signature == 'MZ'

	def __str__(self):
		s = 'Signature: {0}\nLast page size: {1}\nFile pages: {2}\nRelocation item count: {3}\nHeader  paragraphs: {4}\nMinalloc: {5}\nMaxalloc: {6}\nInitial SS value: {7}\nInitial SP value: {8}\nChecksum: {9}\nInitial IP value:{10}\nInitial CS value (pre-relocation): {11}\nRelocation table offset: {12}\nOverlay number: {13}\nRelocation table:\n'.format(self.signature, self.last_page_size, self.file_pages, self.relocation_item_count, self.header_paragraphs, self.minalloc, self.maxalloc, self.initial_ss_value, self.initial_sp_value, self.checksum, self.initial_ip_value, self.initial_cs_value, self.relocation_table_offset, self.overlay_number)
		for i in self.relocation_table:
			s += '\tOffset: {0}\n\tSegment address: {1}'.format(i['offset'], i['segment_address'])

		return s

parser = argparse.ArgumentParser(description='Disasm a dos exe')
parser.add_argument('exe_path')
args = parser.parse_args()

paragraph_size_in_bytes = 16
page_size_in_bytes = 512

with open(args.exe_path, 'rb') as f:
	header = DOSHeader(f)

	if header.is_mz():
		print(header)
		offset = header.header_paragraphs * paragraph_size_in_bytes
		f.seek(offset)
		code_size = header.file_pages * page_size_in_bytes + header.last_page_size
		code = f.read(code_size)
	else:
		f.seek(0)
		code = f.read()

print(code)

from disassembler import Disassembler

d = Disassembler(code, 0x100)
d.disasm(0x100, 0)
d.write('./out.s')

'''
from capstone import *

md = Cs(CS_ARCH_X86, CS_MODE_16)
md.detail = True

ip = 0x100

entry_points = []

def disasm(all_code, subcode, ip, f):
	if ip in entry_points:
		return
	else:
		print('New entry point 0x%x' %(ip))
		entry_points.append(ip)

	for i in md.disasm(subcode, ip):
		print('0x%x: \t%s\t%s\t%s' %(i.address, ''.join('{:02x}'.format(x) for x in i.bytes), i.mnemonic, i.op_str))
		f.write(i.mnemonic + '\t' + i.op_str)
		if CS_GRP_JUMP in i.groups:
			print('Got a jump')
			target = i.operands[0].value.imm
			disasm(all_code, all_code[target-0x100:], target, f)
			return

with open('out.asm', 'w') as f:
	disasm(code, code, ip, f)
	for i in md.disasm(code, 0x100, 1):
		target = i.operands[0].value.imm
		print('0x%x' %(target))
		subs = code[target-0x100:]

	for i in md.disasm(subs, target, 1):
		print('0x%x: \t%s\t%s' %(i.address, i.mnemonic, i.op_str))
'''
