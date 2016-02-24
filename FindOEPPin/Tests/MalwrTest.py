import subprocess, time, sys, os

print("\nScript Started")

malware_folder = "C:\\Users\\sebastiano\\Desktop\\vbox_shared\\Malwares"

while 1:

	if len(os.listdir(malware_folder)) == 0:
		print('Analysis completed')
		sys.exit(1)

	print("\nRestoring Virtual Machine")
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe snapshot Windows7Reverse restore Windows7ReverseOriginal")
	p.wait()

	print("\nStarting Virtual Machine")
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe startvm Windows7Reverse")
	p.wait()

	print("\nRun script")
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe guestcontrol Windows7Reverse run --username phate --password phate -- C:\\pin\\MalTester.bat")
	p.wait()

	print("\nShutting down Virtual Machine")
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe controlvm Windows7Reverse poweroff")
	p.wait()