import argparse

from moderniser import *

def read_word(f):
	import struct
	return struct.unpack('h', f.read(2))[0]

class DOSHeader:
	def __init__(self, f):
		self.signature = f.read(2).decode('ascii')
		if not self.is_mz:
			print('Assuming com file (first 2 bytes: %s)' %self.signature)
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

	@property
	def is_mz(self):
		return self.signature == 'MZ'

	def __str__(self):
		s = 'Signature: {0}\nLast page size: {1}\nFile pages: {2}\nRelocation item count: {3}\nHeader  paragraphs: {4}\nMinalloc: {5}\nMaxalloc: {6}\nInitial SS value: {7}\nInitial SP value: {8}\nChecksum: {9}\nInitial IP value:{10}\nInitial CS value (pre-relocation): {11}\nRelocation table offset: {12}\nOverlay number: {13}\nRelocation table:\n'.format(self.signature, hex(self.last_page_size), self.file_pages, self.relocation_item_count, self.header_paragraphs, self.minalloc, self.maxalloc, hex(self.initial_ss_value), hex(self.initial_sp_value), self.checksum, hex(self.initial_ip_value), hex(self.initial_cs_value), hex(self.relocation_table_offset), self.overlay_number)
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

	if header.is_mz:
		print(header)
		offset = header.header_paragraphs * paragraph_size_in_bytes
		f.seek(offset)
		code_size = header.file_pages * page_size_in_bytes + header.last_page_size
		code = f.read(code_size)
		offset = 0
		entry_point = header.initial_cs_value * 0x10 + header.initial_ip_value
	else:
		f.seek(0)
		code = f.read()
		offset = 0x100
		entry_point = 0x100

print('Executable at offset %s, entry point %s' %(hex(offset), hex(entry_point)))

with open('out.exe.stripped', 'wb') as f:
	f.write(code)

from disassembler import Disassembler

d = Disassembler(code, offset, args.exe_path, header, Disassembler.TargetBits.x32)
cfg = d.disasm(entry_point)
d.write('./out.s')

moderniser = Moderniser(cfg)
moderniser.find_const_int21s()
