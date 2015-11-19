import re
import sys

entry_point = "00401220" # we know this a priori 
ep_index = -1

scale = 0.01 #scale factor to divide the write-sets size
classes = []
counter_list = [0] * 101 # 1 to 1 correspondence with the classes ( they are always 100 ) 

unique_write_set_index = []


def generate_classes(fraction,size):
	
	cont = 0
	classes.append([cont,int(fraction)])
	cont = 1
	acc = int(fraction)
	acc = acc + fraction
	#print "size is" + str(size)
	while acc < size:
		classes.append([cont,int(acc)])
		acc = acc + int(fraction)
		cont = cont + 1

	classes.append([cont,int(acc)])
	#print classes
	#print len(classes)


def insert_in_classes(delta_jmp,oep_flag):
    
	global ep_index

	if delta_jmp <= classes[0][1]:
			counter_list[classes[0][0]] = counter_list[classes[0][0]] + 1
			if oep_flag == 1:
				ep_index = 0
			return

	if delta_jmp >= classes[100][1]:
			counter_list[classes[100][0]] = counter_list[classes[100][0]] + 1
			if oep_flag == 1:
				ep_index = 100
			return
		
	for i in range(len(classes)-1):
		#print classes[i]
		if delta_jmp >= classes[i][1] and delta_jmp < classes[i+1][1]:
			counter_list[classes[i][0]] = counter_list[classes[i][0]] + 1
			if oep_flag == 1:
				ep_index = i
			return

			



if len(sys.argv) != 2:
	print "File name needed"
	sys.exit(0)
try:
	in_file = open(sys.argv[1],"r")
except IOError:
	print "File not found"
	sys.exit(0)




# parse the unique write set indexes in the file 
for line in in_file:
	splitted = line.strip().split(",") 
	if len(splitted) < 4: # last element is garbage 
		continue
	wtis = splitted[3].strip()[17:]
	wsize = splitted[4].strip()[21:]

	witem_info = [wtis,wsize]
	if witem_info not in unique_write_set_index:
		unique_write_set_index.append(witem_info)

#print str(unique_write_set_index) + "\n"

for witem in unique_write_set_index:

	in_file.seek(0)
	size = int(witem[1],10) # get the size from the witem 
	index = witem[0] # get the index
	fraction = size * scale 

	generate_classes(fraction,size)

	#print classes 

	for line in in_file:
		splitted = line.strip().split(",") 
		#print splitted
		if len(splitted) < 4: # last element is garbage 
			continue
		wtis = splitted[3].strip()[17:]
		oep = splitted[1].strip()[11:]

		if index == wtis: # if the current analyzed long jump is in the current write set analyzed 
			delta_jmp = int(splitted[2].strip()[12:],10)
			#print delta_jmp
			if oep == entry_point:
				insert_in_classes(delta_jmp,1)
			else:
				insert_in_classes(delta_jmp,0)

	#print "\n"
	#print counter_list
	#print "\n"

	print "Write set size: " + str(size) + "\n"

	k=0
	#print ep_index
	for c in classes:
		if str(c[0]) == str(ep_index): 
			print str(int(c[0])+1) +"/100 : " + str(counter_list[k]) + " <-- [x]oep here" + "\n"
		else:
			print str(int(c[0])+1) +"/100 : " + str(counter_list[k]) + "\n"

		k = k+1

	counter_list = [0] * 101
	classes = []
	ep_index = -1