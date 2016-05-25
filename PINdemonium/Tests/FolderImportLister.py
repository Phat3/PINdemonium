from subprocess import check_output
from os import listdir
from os.path import isfile, join


ida_path = "C:\\Program Files\\IDA 6.6\\idaw.exe"
importLister_script = "C:\\Users\\phate\\Desktop\\FindOEPPin\\FindOEPPin\\Tests\\importLister.py"


def generateImportsFile(mypath):
  files = [f for f in listdir(mypath) if isfile(join(mypath, f))]
  for cur_file in files:
    if cur_file.split(".")[-1] == "exe":
      out_file = "".join(cur_file.split(".")[:-1]) + "_imports.txt"
      importLister_command = "\"" + ida_path + "\"" + " -A -S"+"\""+importLister_script + " " + join(mypath, out_file)  + "\""+ " " + "\"" + join(mypath, cur_file) + "\""
      print(importLister_command)
      try:
        check_output(importLister_command,shell=True)
      except Exception as e:
        print("error "+str(e)+" processing "+importLister_command)
        
