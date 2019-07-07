import argparse

def read_word(f):
	import struct
	return struct.unpack('h', f.read(2))[0]

class DOSHeader:
	def __init__(self, f):
		self.signature = f.read(2)
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
	print(header)

	f.seek(header.header_paragraphs * paragraph_size_in_bytes)
	code_size = header.file_pages * page_size_in_bytes + header.last_page_size
	code = f.read(code_size)
	print(code)
