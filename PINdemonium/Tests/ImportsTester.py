from os.path import isfile, isdir, join
from os import listdir, rename
import subprocess
import time
import sys
import shutil
import json
import FolderImportLister
from FolderImportLister import generateImportsFile

"""
    IN ORDER TO MAKE THE SCRIPT WORK FOLLOW THIS STEPS:
    
    1.  Run the analysis script MalTester.py (BE CAREFUL: this script also requires some configuration)
    2.  Create a folder named Malware_Results in your desktop and put the results of the analysis in this folders
    3.  Put this script, FolderImportLister.py and importLister.py in the same folder
    4.  Eventually change che path in the FolderImportLister.py
    5.  Now just rin this script and see the result in the results.txt file
    
"""

malware_folder = "E:\\Results"
result_file_name = "results.txt"
final_report_file_name = "report_FindOEPPin.txt"

def analyseTests():
  #get the list of folders of results to analize
  malwares_results = [f for f in listdir(malware_folder)]
  length = len(malwares_results)
  
  if length == 0:
    print("Malware Results folder empty")
    return None
  
  for i in range(0,length):
    #path to a single folder of a malware result
    folder_path = join(malware_folder,malwares_results[i])
    generateImportsFile(folder_path)

    #path to the original imports file of a malware result folder
    original_imports_path = join(folder_path,"original_imports.txt")
    best_dump = -1
    best_number_new_imports = -1
    best_zero_count = -1

    if isfile(original_imports_path):
      #rename the malware sample to its SHA1
      original_malware_path = join(folder_path, malwares_results[i]) + ".exe"
      shutil.move(join(folder_path, "original.exe"), original_malware_path)
      #get the original imports of the malware
      original_imports_file = open(original_imports_path, "r")
      original_imports = original_imports_file.readlines()
      #get the report file
      final_report_file_path = join(folder_path, final_report_file_name)
      final_report_file = open(final_report_file_path, "r")
      final_report_lines = final_report_file.readlines()
      dump_number = -1
      #get the imports of each dump
      for cur_file in listdir(folder_path):
        splitted_name = cur_file.split("_")
        if len(splitted_name) == 3:
          dump_number = cur_file.split("_")[1]
        if any("imports.txt" in s for s in splitted_name) and not(any("original" in s for s in splitted_name)):
          dump_import_path = join(folder_path, cur_file)
          dump_imports_file = open(dump_import_path, "r")
          dump_imports = dump_imports_file.readlines()
          for f in dump_imports:
            if f == "?\n":
              dump_imports.remove(f)
          #compare the dump imports with the original ones and the zero count with the previously saved value and eventually update the best results
          zero_count = len( dict((key, val) for key, val in json.loads(final_report_lines[int(dump_number)]).items() if (all(x == '0' for x in val) and key != 'dump number')) )
          new_dump_imports = list(set(dump_imports) - set(original_imports))
          if (len(new_dump_imports) >= best_number_new_imports and zero_count >= best_zero_count):
            best_zero_count = zero_count
            best_dump = cur_file
            best_number_new_imports = len(new_dump_imports)

    #save the results for the current malware
    result_file_path = malware_folder + "\\" + malwares_results[i] + "\\" + result_file_name
    result_file = open(result_file_path, "a")
    result_file.write("Malware: " + str(malwares_results[i]) + ", best_number_new_imports: " + str(best_number_new_imports) + ", best zero count: " + str(best_zero_count) + ", best dump: " + str(best_dump) + "\n")
          
def main():
  analyseTests()

main()
