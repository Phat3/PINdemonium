from os.path import isfile, isdir, join
import os
import subprocess32
import time
import sys
import shutil
import signal


'''
To use this script:
  1) Put the malwares in the malware_folder (E:\Malwares)
  2) Create a work_folder where the malwares will be copied to and run (C:\Users\phate\Desktop\MalwareTests)
  3) Create a Result folder(test_results) where the results of the unpacking will be saved (E:\Results)
  4) Run the tool from the pin directory to avoid Scyllax86.dll problem (dll not found) python C:\Users\phate\MalTester.py

'''

malware_folder = "E:\\Malwares\\"
work_folder = "C:\\Users\\phate\\Desktop\\MalwareTests\\"
pin_executable = "C:\\pin\\pin.exe "
pin_tool ="C:\\pin\\FindOEPPin.dll"
pin_results = "C:\\pin\\PinUnpackerResults\\"
test_results = "E:\\Results\\"
connect_network_folder = "net use E: \\\\vboxsvr\\vbox_shared"
disconnect_network_folder = "net use E: /del"

def getCurrentMalware():
  #get the list of malwares to analize
  malwares = [f for f in os.listdir(malware_folder) if isfile(join(malware_folder, f))]
  if len(malwares) == 0:
    print("Malware folder empty")
    return None
  print("Current malwares "+str(malwares))
  #move the malware to the work folder
  from_path = join(malware_folder,malwares[0])  
  to_path = join(work_folder,malwares[0]+".exe")
  print("Moving malware to " +to_path)
  shutil.move(from_path,to_path)
  #subprocess32.call(disconnect_network_folder, shell=True)
  return to_path



def executePin(cur_malware):
  command = "%s -t %s -unp -antiev -antiev-ins -adv-iatfix -iwae 2 -- %s "%(pin_executable,pin_tool, cur_malware)
  print("launching " + command)
  proc = subprocess32.Popen(command, shell=True)
  print(proc.pid)
  pid_malware = 0
  malware_name = cur_malware.split("\\")[-1]
  try:
  	proc.wait(300)
  except Exception:
  	print("timer expired!!!") 
  	os.system("taskkill /F /IM " + malware_name)
  	malware_name = cur_malware.split("\\")[-1]
  	moveResults(malware_name)
  	sys.exit(0)


def moveResults(cur_malware):
  result = [f for f in os.listdir(pin_results) if isdir(join(pin_results, f))]
  if len(result) == None:
    print("No result folder created")
    return
  # C:\\pin\PinUnpackerResults\\date\..
  pin_res_dir = join(pin_results,result[0])
  # name of the malware
  cur_mal_folder = cur_malware.split(".")[0]
  print("malware folder "+ cur_mal_folder)
  # E:\\Results\\malware_name
  test_res_dir = join(test_results,cur_mal_folder)
  print("Moving result directory from %s to %s "%(pin_res_dir,test_res_dir))
  os.makedirs(test_res_dir)
  # move all folders into E:\\Results
  for f in os.listdir(pin_res_dir):
  	shutil.move(pin_res_dir + "\\" + f, test_res_dir + "\\" + f)
  # E:\\Results\\malware_name\\original.exe
  original_malware_path = join(test_res_dir, "original.exe")

  shutil.move(join(work_folder,cur_malware), original_malware_path)
  #subprocess32.call(disconnect_network_folder, shell=True)

  

def main():
  #subprocess32.call(connect_network_folder, shell=True)
  if not os.path.exists(work_folder):
  	os.makedirs(work_folder)
  if not os.path.exists(test_results):
  	os.makedirs(test_results)
  for file in os.listdir(pin_results):
  	print file
  	shutil.rmtree(pin_results + file)
  cur_malware = getCurrentMalware()
  if cur_malware != None:  
    executePin(cur_malware)
    malware_name = cur_malware.split("\\")[-1]
    moveResults(malware_name)
    sys.exit(0)

main()