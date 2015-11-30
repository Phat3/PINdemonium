import json

report_file = open('report_FindOEPPin.txt','r')

index_best_dump = -1
zero_count_best = 0
functions_detected_best = -1
i = 0 

for line in report_file:
        new_dict = dict(json.loads(line).items())
        print "Parsing dump number " + str(new_dict['dump number'])
        if new_dict['runnable?'] == 'PROBABLY YES':
                zero_count = len( dict((key, val) for key, val in json.loads(line).items() if all(x == '0' for x in val)) )	#filter all the val that is not 0 and get the count of the resulting dict
                functions_detected = new_dict['detected_functions'].split("/")[0]                                               #count the number of detected import funtions
                print "-> zero count: " + str(zero_count)
                print "-> number of malicious imported functions detected: " + str(functions_detected)
                if functions_detected > functions_detected_best and zero_count > zero_count_best:
                        zero_count_best = zero_count
                        index_best_dump = new_dict['dump number']
                i = i + 1
        else:
                print "-> dump not runnable"
        print "-------------------------------------------------------"

print "\n"
print "BEST DUMP IS : " + str(index_best_dump)
