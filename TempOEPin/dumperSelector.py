import json

report_file = open('C:\\pin\\TempOEPin\\27_10_2015_03_21_42\\report_FindOEPPin.txt','r')

index_best_dump = 0
zero_count_best = 0
i = 0 

for line in report_file:
	zero_count = len( dict((key, val) for key, val in json.loads(line).items() if all(x == '0' for x in val)) )	#filter all the val that ius not 0 and get the count of the resulting dict
	if zero_count > zero_count_best:
		zero_count_best = zero_count
		index_best_dump = i
	i = i + 1

print "BEST DUMP IS : " + str(index_best_dump)