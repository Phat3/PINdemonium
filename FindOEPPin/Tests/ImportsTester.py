from os.path import isfile, isdir, join
from os import listdir, rename
import subprocess
import time
import sys
import shutil
import json

malware_folder = "C:\\Users\\phate\\Desktop\\Malware Results\\"

def getCurrentMalware():
  #get the list of folders of results to analize
  malwares_results = [f for f in listdir(malware_folder)]
  length = len(malwares_results)
  if length == 0:
    print("Malware Results folder empty")
    return None
  for i in range(0,length):
    #path to a single folder of a malware result
    partial_path = join(malware_folder,malwares_results[i])
    #path to the report file of a malware result
    complete_path = join(partial_path,"report_FindOEPPin.txt")
    if isfile(complete_path):
      report_file = open(complete_path,'r')
      print "\n-------------MALWARE " + str(malwares_results[i]) + "-------------\n"
      index_best_dump = -1
      functions_detected_best = -1
      for line in report_file:
          new_dict = dict(json.loads(line).items())
          print "Parsing dump number " + str(new_dict['dump number'])
          if new_dict['runnable?'] == 'PROBABLY YES':
                  functions_detected = new_dict['detected_functions'].split("/")[0]                                               #count the number of detected import funtions
                  print "-> number of malicious imported functions detected: " + str(functions_detected)
                  if functions_detected > functions_detected_best:
                          functions_detected_best = functions_detected
                          index_best_dump = new_dict['dump number']
                  i = i + 1
          else:
                  print "-> dump not runnable"
          print "-------------------------------------------------------"
 
def main():
  getCurrentMalware()

main()


  
