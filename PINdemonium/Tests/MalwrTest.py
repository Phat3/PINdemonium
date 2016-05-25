import subprocess, time, sys, os, shutil

print("\nScript Started")

malware_folder = "C:\\Users\\sebastiano\\Desktop\\vbox_shared\\Malwares\\"
test_results_guest = "C:\\Users\\sebastiano\\Desktop\\vbox_shared\\Results\\" 
test_results_host = "C:\\Users\\sebastiano\\Desktop\\test_results\\" 

if not os.path.exists(test_results_host):
  	os.makedirs(test_results_host)

while 1:

	if len(os.listdir(malware_folder)) == 0:
		print('Analysis completed')
		sys.exit(1)

	print("\nRestoring Virtual Machine")
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe snapshot Windows7Reverse restore Windows7RevereseOriginal")
	p.wait()

	print("\nStarting Virtual Machine")
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe startvm Windows7Reverse")
	p.wait()

	print("\nRun script")
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe guestcontrol Windows7Reverse run --username phate --password phate -- C:\\pin\\MalTester.bat")
	p.wait()

	print("\nAnalyze imports")
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe guestcontrol Windows7Reverse run --username phate --password phate -- C:\\pin\\ImportsTester.bat")
	p.wait()

	print("\nMove results")
	for f in os.listdir(test_results_guest):
		print(f + " moved")
		shutil.move(test_results_guest + f, test_results_host + f)

	print("\nShutting down Virtual Machine")
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe controlvm Windows7Reverse poweroff")
	p.wait()