'''
 Problemi & Riflessioni:

 1- posso prendere le xrefs agli indirizzi delle heapzone, ma se ad esempio viene spostato in
    un registro una costante che rappresenta un indirizzo, e viene poi fatta una call a quell'indirizzo ( mov eax, 0x2cc0000; call eax; )
    quel riferimento non viene visto da IDA e non posso quindi accorgermi che è necessario aggingere quella heapzone
    ( si potrebbe dire, ok io ti metto quelle che trovo, il resto le aggiungi tu a mano se servono )
 
 2- Devo checkare per ogni indirizzo all'interno dell'heapzone se ci sono XrefsTo a quell'inidirizzo. Questo processo potrebbe 
    essere dispendioso qualora ci siano molte heap-zone parecchio grosse. In questo modo oltretutto bisognerebbe controllare
    se all'interno delle heapzone ci sono altri indirizzi non risolti! L'approccio migliore per risolvere questi problemi
    sembra quello di aggiungere tutte le heapzone all'idb, in modo tale che tutte le crossreference sono già a posto ( infatti aggiungendo tutto 
    ho automaticamente risolto in un colpo solo tutte le dipendenze tra heapzone ) e non ho il problema di perdermi delle referenze 
    ad indirizzi fatte nel modo discusso nel punto (1)

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

	start_addr = int(line[1],16)
	end_addr   = start_addr + int(line[2],10)

	print "Checking heap zone " + hex(start_addr) + " to " + hex(end_addr) + "\n"

	# in the interheap example the address 0x2cc0000 is never discovered 
	for addr in xrange(start_addr,end_addr):
		gen_xrefs = XrefsTo(addr, 0)
		dat_xrefs = DataRefsTo(addr)
		for xx in gen_xrefs:
			print hex(xx.frm)
		for xx in dat_xrefs:
			print hex(xx)
	
	#heap_bin = open(path + "/heaps/"+line[0]+".bin",'rb')