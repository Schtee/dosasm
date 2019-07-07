import argparse

class DOSHeader:
	def __init__(self, f):
		import struct
		self.signature = f.read(2)
		self.last_page_size = struct.unpack('h', f.read(2))[0]
		self.file_pages = struct.unpack('h', f.read(2))[0]
		self.relocation_item_count = struct.unpack('h', f.read(2))[0]
		self.header_paragraphs = struct.unpack('h', f.read(2))[0]
		self.minalloc = struct.unpack('h', f.read(2))[0]
		self.maxalloc = struct.unpack('h',f.read(2))[0]
		self.initial_ss_value = struct.unpack('h', f.read(2))[0]
		self.initial_sp_value = struct.unpack('h', f.read(2))[0]
		self.checksum = struct.unpack('h', f.read(2))[0]
		self.initial_ip_value = struct.unpack('h', f.read(2))[0]
		self.initial_cs_value = struct.unpack('h', f.read(2))[0] # this is pre-relocation
		self.relocation_table_offset = struct.unpack('h', f.read(2))[0]
		self.overlay_number = struct.unpack('h', f.read(2))[0]

	def __str__(self):
		return 'Signature: {0}\nLast page size: {1}\nFile pages: {2}\nRelocation item count: {3}\nHeader  paragraphs: {4}\nMinalloc: {5}\nMaxalloc: {6}\nInitial SS value: {7}\nInitial SP value: {8}\nChecksum: {9}\nInitial IP value:{10}\nInitial CS value (pre-relocation: {11}\nRelocation table offset: {12}\nOverlay number: {13}'.format(self.signature, self.last_page_size, self.file_pages, self.relocation_item_count, self.header_paragraphs, self.minalloc, self.maxalloc, self.initial_ss_value, self.initial_sp_value, self.checksum, self.initial_ip_value, self.initial_cs_value, self.relocation_table_offset, self.overlay_number)

def read_header(path):
	with open(path, 'rb') as f:
		header = DOSHeader(f)

	return header

parser = argparse.ArgumentParser(description='Disasm a dos exe')
parser.add_argument('exe_path')
args = parser.parse_args()

print(args)
header = read_header(args.exe_path)
#from pprint import pprint
#pprint(vars(header))
print(header)

