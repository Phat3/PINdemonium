'''
 This script will patch the idb
 with all the heap-zone dumped during the unpacking.
'''

import idaapi
import idc
import idautils
import os
import sys

path = '/'.join(GetInputFilePath().split('\\')[:-1])
path = idc.AskStr(path,'Enter path of the dump directory: ')

# Open the heap_map
heapmap = open(path + "/heaps/heap_map.txt",'r')

if heapmap == None:
	print "Wrong path!\n"
	sys.exit(0)

for line in heapmap:
	line = line.split(' ')[:-1]
	
	heap_bin = open(path + "/heaps/"+line[0],'rb')

	heap_bin_size = os.fstat(heap_bin.fileno()).st_size
	start_addr = int(line[1],16)
	end_addr   = start_addr + int(line[2],10)

	# Create a new section that will contain the heap data 
	is32bitSeg = 1 
	SegAlignment = 32
	idc.SegCreate(start_addr,end_addr,0,is32bitSeg,SegAlignment,0)

	# Copy from the heap dump the data inside the new created Section
	addr = start_addr
	for i in xrange(1,heap_bin_size):
		byte = ord(heap_bin.read(1))
		idc.PatchByte(addr,byte)
		addr = NextAddr(addr)
