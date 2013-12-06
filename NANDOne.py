#!/usr/bin/python

APP_NAME = 'NANDOne'
BUILD_VER = 'v0.02'

import sys
import getopt
import struct
import mmap
import os

NAND_SIZE = 0x13C000000
LOG_BLOCK_SZ = 0x1000

MAGIC_SIZE = 0x4

SFBX_MAGIC = 'SFBX'
GFCX_MAGIC = 'GFCX'
GFCU_MAGIC = 'GFCU'

SFBX_START = [0x810000,0x10000]
SFBX_MAGIC_START = 0x0

SFBX_ENTS_START = 0x10
SFBX_ENTS_SIZE = 0x3B0

SFBX_BLOB_START = 0x3C0
SFBX_BLOB_SIZE = 0x40

SFBX_EN_SIZE = 0x10
SFBX_EN_LBA_START = 0x0 
SFBX_EN_SZ_START = 0x4 

SFBX_ENTS_MAXCNT = (SFBX_ENTS_SIZE-SFBX_ENTS_START) / SFBX_EN_SIZE

GFCU_MAGIC_START = 0x28
GFCU_ENTS_START = 0xF0

GFCU_BLOB_START = 0xAD8
GFCU_BLOB_SIZE = 0x64

GFCU_EN_SIZE = 0x4C
GFCU_EN_FN_START = 0x0
GFCU_EN_FN_LENGTH = 0x40
GFCU_EN_SIZE_START = 0x40
GFCU_EN_BLOCK_START = 0x44
GFCU_EN_UNKNOWN_START = 0x48
GFCU_EN_EOF_START = 0x4
GFCU_EN_EOF_MAGIC = 0x3FF

GFCU_ENTS_MAXCNT = 0x100

gfcu_arr = []
sfbx_arr = []

KRNL_VER_START = 0x30
KRNL_VER_LENGTH = 0x70

def ReverseByteOrder(data):
	dstr = hex(data)[2:].replace('L','')
	byteCount = len(dstr[::2])
	val = 0
	for i, n in enumerate(range(byteCount)):
		d = data & 0xFF
		val |= (d << (8 * (byteCount - i - 1)))
		data >>= 8
	return val

def ReadUInt16_LE(data,addr):
	return struct.unpack('<H', data[addr:addr+2])[0]

def ReadUInt16_BE(data,addr):
	return struct.unpack('>H', data[addr:addr+2])[0]

def ReadUInt32_LE(data,addr):
	return struct.unpack('<I', data[addr:addr+4])[0]

def ReadUInt32_BE(data,addr):
	return struct.unpack('>I', data[addr:addr+4])[0]

def ReadString(data,addr,size):
	return data[addr:addr+size]

def GetFilesize(filename):
	st = os.stat(filename)
	return st.st_size

def FileExists(filename):
	return os.path.isfile(filename)

def CheckMagic(indata, pos, magic):
	read = ReadUInt32_LE(indata, pos)
	comp = ReadUInt32_LE(magic, 0)
	if read != comp:
		return -1 # Error
	return 0

def OpenFile(filename, start, length):
	file = open(filename, 'r+b')
	file.seek(start)
	data = file.read(length)
	file.close()
	return data

def ScanSFBX(filename):
	with open(filename, 'r+b') as file:
		mm = mmap.mmap(file.fileno(), 0)
		for i in xrange(0,(NAND_SIZE-LOG_BLOCK_SZ), LOG_BLOCK_SZ):
			sfbx_magic = ReadString(mm, i,len(SFBX_MAGIC))
			if(CheckMagic(sfbx_magic, SFBX_MAGIC_START, SFBX_MAGIC) == 0):
				print('Found \'SFBX\' @ addr {:#09x}!'.format(i))
				print('Append the addr to SFBX_START[]-list!')
				return i
		return 0
	mm.close()
	
def DumpSFBX(filename):
	with open(filename, 'r+b') as file:
		mm = mmap.mmap(file.fileno(), 0)
		for i in xrange(len(SFBX_START)):
			sfbx_magic = ReadString(mm, SFBX_START[i],len(SFBX_MAGIC))
			if(CheckMagic(sfbx_magic, SFBX_MAGIC_START, SFBX_MAGIC) == 0):
				addr = SFBX_START[i] + SFBX_ENTS_START
				break	
			if (i == len(SFBX_START)-1):
				return 0
		
		#Read adresses in array		
		for j in xrange(SFBX_ENTS_MAXCNT):
			total_pos = addr + j * SFBX_EN_SIZE
			entry = ReadString(mm, total_pos, SFBX_EN_SIZE)

			lba = ReadUInt32_LE(entry, SFBX_EN_LBA_START)
			sz = ReadUInt32_LE(entry, SFBX_EN_SZ_START)
			
			magic = ReadString(mm, lba * LOG_BLOCK_SZ, MAGIC_SIZE)
			
			sfbx_arr.append([])
			sfbx_arr[-1].append(total_pos)
			sfbx_arr[-1].append(lba)
			sfbx_arr[-1].append(sz)
			sfbx_arr[-1].append(magic)
	mm.close()
	return j-1

def ExtractSFBXData():
	with open(filename, 'r+b') as infile:
		mm = mmap.mmap(infile.fileno(), 0)
		count = 0
		for i in xrange(len(sfbx_arr)):
			if (sfbx_arr[i][1] != 0) and (sfbx_arr[i][2] != 0):
				count = count + 1
				addr = sfbx_arr[i][1] * LOG_BLOCK_SZ
				size = sfbx_arr[i][2] * LOG_BLOCK_SZ
				magic = sfbx_arr[i][3]
			
				if (magic.isalpha()):
					fn_out = '{:#02}_{}.bin'.format(count,magic)
				else:
					fn_out = '{:#02}.bin'.format(count)
				outfile = open(fn_out, 'w+b')
				print('Extracting @ {:#08x}, size: {}kb to \'{}\''.\
						format(addr,size/1024,fn_out))
				outfile.write(mm[addr:addr+size])	
				outfile.close()

	mm.close()

def PrintSFBX():
	print('\nSFBX Entries')
	print('-----------\n')
	for i in xrange(len(sfbx_arr)):
		if (sfbx_arr[i][1] == 0):
			continue                                               
		print('Entry 0x{0:02X} : found @ pos: {1:08X}'.\
				format(i, sfbx_arr[i][0]))
		print('\tLBA: {0:08X} (addr {1:09X})'.\
				format(sfbx_arr[i][1], (sfbx_arr[i][1] * LOG_BLOCK_SZ)))
		print('\tSize: {0:08X} ({0} Bytes, {1}kB, {2}MB)'.\
				format((sfbx_arr[i][2] * LOG_BLOCK_SZ),\
					(sfbx_arr[i][2] * LOG_BLOCK_SZ)/1024,\
					(sfbx_arr[i][2] * LOG_BLOCK_SZ)/1024/1024))
		if (sfbx_arr[i][3].isalpha()):
			print('*** MAGIC: {0} ***'.\
				format(sfbx_arr[i][3]))

# Returns: total addr, total_size 		
def GetEntryByMagic(magic):
	for i in xrange(len(sfbx_arr)):
		if (sfbx_arr[i][3] == magic):
			return (sfbx_arr[i][1] * LOG_BLOCK_SZ),\
					(sfbx_arr[i][2] * LOG_BLOCK_SZ)
	return 0

# Returns: total_size
def GetEntryByAddr(addr):
	for i in xrange(len(sfbx_arr)):
		if ((sfbx_arr[i][1] * LOG_BLOCK_SZ) == addr):
			return (sfbx_arr[i][2] * LOG_BLOCK_SZ)
	return 0

def DumpKernelVer(data):
	return ReadString(data,KRNL_VER_START, KRNL_VER_LENGTH)

def DumpGFCU(data,startaddr):
	for i in xrange(GFCU_ENTS_MAXCNT):
		pos = startaddr + i*GFCU_EN_SIZE
		entry = data[pos:pos+GFCU_EN_SIZE]

		eof = ReadUInt32_LE(entry, GFCU_EN_EOF_START)
		if (eof == GFCU_EN_EOF_MAGIC):
			return i-1

		fn = ReadString(entry, GFCU_EN_FN_START, GFCU_EN_FN_LENGTH)
		sz = ReadUInt32_LE(entry, GFCU_EN_SIZE_START)
		blk = ReadUInt32_LE(entry, GFCU_EN_BLOCK_START)
		un = ReadUInt32_LE(entry, GFCU_EN_UNKNOWN_START)

		gfcu_arr.append([])
		gfcu_arr[-1].append(pos)
		gfcu_arr[-1].append(fn)
		gfcu_arr[-1].append(sz)
		gfcu_arr[-1].append(blk)
		gfcu_arr[-1].append(un)
				
def PrintGFCU():
	print('\nGFCU Entries')
	print('-----------\n')
	for i in xrange(len(gfcu_arr)):	                                               
		print('Entry 0x{0:02X} : found @ pos: {1:08X}'.\
				format(i, gfcu_arr[i][0]))
		print('\tfilename: {0} (size: {1:09X})'.\
				format(gfcu_arr[i][1], (gfcu_arr[i][2] * LOG_BLOCK_SZ)))
		print('\tBlock: {0:08X} Unknown: {0:08X}'.\
				format((gfcu_arr[i][3] * LOG_BLOCK_SZ),\
					(gfcu_arr[i][4] * LOG_BLOCK_SZ)))

action_arr = 	['sfbxscan','Scans for SFBX address'],\
				['info', 'Prints the parsed entries'],\
				['extract','Extracts nand content']

def PrintUsage():
	print('Usage:')
	print('\t{0} [action] [dump]'.format(sys.argv[0]))
	print('\nAvailable Action:')
	for i in xrange(len(action_arr)):
		print ('\t{0}\t\t{1}'.format(action_arr[i][0], action_arr[i][1]))
	print('\nExample:')
	print('\t{0} {1} nanddump.bin'.format(sys.argv[0], action_arr[0][0]))

if __name__ == '__main__':
	print('{} {} started\n'.format(APP_NAME, BUILD_VER))
	if len(sys.argv) != 3:
		PrintUsage()
		sys.exit(-1)
	for i in xrange(len(action_arr)):
		if (sys.argv[1] == action_arr[i][0]):
			break
		elif (i == len(action_arr)-1):
			print('ERROR: [action] parameter is invalid!\n')
			PrintUsage()
			sys.exit(-2)
	if (FileExists(sys.argv[2]) == 0):
		print('ERROR: file \'{}\' doesn\'t exist\n'.format(sys.argv[2]))
		PrintUsage()
		sys.exit(-3)
		
############
### MAIN ###
############

action = sys.argv[1]
filename = sys.argv[2]

print('Opening \'{}\''.format(filename))

if (GetFilesize(filename) != NAND_SIZE):
	print('Invalid filesize. Aborting!')
	sys.exit(-4)

if (action == action_arr[0][0]): # 'sfbxscan'
	ScanSFBX(filename)
	sys.exit(-4)

print('\nDumping SFBX Entries... ')
sfbx_len = DumpSFBX(filename)
if (sfbx_len == 0):
	print('SFBX not found! Aborting!\n')
	sys.exit(-4)
print('Found {} Entries\n'.format(sfbx_len))


gfcx_addr, gfcx_size = GetEntryByMagic(GFCX_MAGIC)
if (gfcx_addr == 0):
	print ('GFCX MAGIC not found. Exiting!')
	sys.exit(-4)
	
gfcu_addr = gfcx_addr + gfcx_size
gfcu_size = GetEntryByAddr(gfcu_addr)

if (gfcu_size == 0):
	print ('GFCU Entry not found. Exiting!')
	sys.exit(-4)

gfcu = OpenFile(filename, gfcu_addr, gfcu_size)
if CheckMagic(gfcu, GFCU_MAGIC_START, GFCU_MAGIC) == -1:
	print ('GFCU MAGIC not found. Exiting!')
	sys.exit(-4)

print('Dumping GFCU Entries... ')
gfcu_len = DumpGFCU(gfcu,GFCU_ENTS_START)
print('Found {} Entries\n'.format(gfcu_len))

print('Xbox ONE Kernel-Version: {}'.format(DumpKernelVer(gfcu)))
	

if (action == action_arr[1][0]): # 'info'
	PrintSFBX()
	PrintGFCU()
elif (action == action_arr[2][0]): # 'extract'
	ExtractSFBXData()
