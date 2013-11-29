#!/usr/bin/python

import sys
import struct

NAND_SIZE = 0x13C000000
MAGIC_SIZE = 0x4

# PARTITION_MAGIC = 'SFBX'.encode('hex')
ENTRY_END_MAGIC  = '01000000'.decode('hex')
FILETABLE_MAGIC = '07000140'.decode('hex')

# PARTITION_START = 0x10000

FILETABLE_START = 0x95C000
FILETABLE_SIZE = 0x700 # enough for filetable of kernel 10210

KERNELVERSION_START = 0x30
KERNELVERSION_LENGTH = 0x70

ENTRIES_START = 0xF0
ENTRIES_MAXCNT = 0x100

ENTRY_SIZE = 0x4C
ENTRY_FILENAME_START = 0x0
ENTRY_FILENAME_LENGTH = 0x40
ENTRY_SIZE_START = 0x40
ENTRY_SIZE_LENGTH = 0x4
ENTRY_BLOCK_START = 0x44
ENTRY_BLOCK_LENGTH = 0x4
ENTRY_END_START = 0x48
ENTRY_END_LENGTH = 0x4


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Xbox ONE NAND-Dump Parser alpha 0.001\n'
        print 'Usage:'
        print '\t{0} [dump]'.format(sys.argv[0])
        print 'Example:'
        print '\t{0} nanddump.bin'.format(sys.argv[0])
        print
        sys.exit(-1)

filename = sys.argv[1]

# Open NAND Dump
file = open(filename, 'rb')
file.seek(FILETABLE_START)
data = file.read(FILETABLE_SIZE)
file.close()

# Check Magic - Not sure if it's a valid magic?!
if data[:MAGIC_SIZE] != FILETABLE_MAGIC:
	print "Filetable MAGIC doesn't match"
	print "Expected 0x{0}, got 0x{1}".\
			format(FILETABLE_MAGIC.encode('hex'),data[:MAGIC_SIZE].encode('hex'))
	sys.exit(-2)

kernelversion = data[KERNELVERSION_START:\
					KERNELVERSION_START+KERNELVERSION_LENGTH]
print "\nXbox ONE Kernel-Version: {0}\n".format(kernelversion)

# Loop through file-entries
for i in xrange(ENTRIES_MAXCNT):
	cur_entry_pos = ENTRIES_START + i*ENTRY_SIZE
	cur_entry = data[cur_entry_pos : cur_entry_pos+ENTRY_SIZE]
	
	if cur_entry[ENTRY_END_START:\
				ENTRY_END_START+ENTRY_END_LENGTH] != ENTRY_END_MAGIC:
		print "\nSeems like we hit last entry"
		sys.exit(-3)

	cur_entry_fn = cur_entry[ENTRY_FILENAME_START :\
							ENTRY_FILENAME_START+ENTRY_FILENAME_LENGTH]
	cur_entry_sz = struct.unpack("<i", cur_entry[ENTRY_SIZE_START :\
							ENTRY_SIZE_START+ENTRY_SIZE_LENGTH])[0]
	cur_entry_blk = struct.unpack("<i", cur_entry[ENTRY_BLOCK_START :\
							ENTRY_BLOCK_START+ENTRY_BLOCK_LENGTH])[0]

	cur_entry_addr = FILETABLE_START+cur_entry_pos
	
	print "Entry {0:#02} : Found @ addr {1:#x} : filename: {2}, size: {3:#x} ({3} bytes), block-offset: {4:#x}".\
           format(i,cur_entry_addr,cur_entry_fn,cur_entry_sz,cur_entry_blk)
