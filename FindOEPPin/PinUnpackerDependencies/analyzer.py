import re
import sys

#counters[0] -> order of magnitude 10^0
#counters[1] -> order of magnitude 10^1
#...
counters = [0] * 10 
legend = "[10^0 10^1 10^2 10^3 10^4 10^5 10^6 10^7 10^8 10^9]"

if len(sys.argv) != 2:
	print "File name needed"
	sys.exit(0)

try:
	in_file = open(sys.argv[1],"r")
except IOError:
	print "File not found"
	sys.exit(0)

for line in in_file:
	magnitude = 0
	splitted = line.strip().split("\t")  #splitted[0] = frequency , splitted[1] = delta_jump_value 
	#print splitted[0] + " " + splitted[1]
	result = int(splitted[1],10)
	#print "analyzing " + str(result)
	while result > 9:
		result = result / 10
		magnitude = magnitude + 1
	if magnitude != 0:
		#print "incrementing" + str(magnitude)
		counters[magnitude] = counters[magnitude] + int(splitted[0],10)

print "[Warning] 10^0 order of magnitude is filtered\n"		
print "\n" + legend + "\n\n" + str(counters)