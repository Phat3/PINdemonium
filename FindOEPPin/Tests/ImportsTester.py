from os.path import isfile, isdir, join
from os import listdir, rename
import subprocess
import time
import sys
import shutil
import json
import FolderImportLister
from FolderImportLister import generateImportsFile

malware_folder = "C:\\Users\\phate\\Desktop\\Malware_Results\\"
result_file_name = "results.txt"

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

    if isfile(original_imports_path):
      #rename the malware sample to its SHA1
      original_malware_path = join(folder_path, malwares_results[i]) + ".exe"
      shutil.move(join(folder_path, "original.exe"), original_malware_path)
      #get the original imports of the malware
      original_imports_file = open(original_imports_path, "r")
      original_imports = original_imports_file.readlines()
      #get the imports of each dump
      for cur_file in listdir(folder_path):
        splitted_name = cur_file.split("_")
        if any("imports.txt" in s for s in splitted_name) and not(any("original" in s for s in splitted_name)):
          dump_import_path = join(folder_path, cur_file)
          dump_imports_file = open(dump_import_path, "r")
          dump_imports = dump_imports_file.readlines()
          for f in dump_imports:
            if f == "?\n":
              dump_imports.remove(f)
          #compare the dump imports with the original ones and eventually update the best results
          new_dump_imports = list(set(dump_imports) - set(original_imports))
          if (len(new_dump_imports) > best_number_new_imports):
            best_dump = cur_file
            best_number_new_imports = len(new_dump_imports)

    #save the results for the current malware
    result_file_path = join(malware_folder, result_file_name)
    result_file = open(result_file_path, "a")
    result_file.write("Malware: " + str(malwares_results[i]) + ", best_number_new_imports: " + str(best_number_new_imports) + ", best dump: " + str(best_dump) + "\n")
          
def main():
  analyseTests()

main()
