import subprocess, time

print "\nScript Started"

time.sleep(10)

while 1:

	print "\nRestoring Virtual Machine"
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe snapshot Windows7Reverse_1 restore BeforeTestsFinal")
	p.wait()

	print "\nStarting Virtual Machine"
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe startvm Windows7Reverse_1")
	p.wait()

	print "\nResetting Virtual Machine"
	#In order to trigger the startup event that triggers the python script
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe controlvm Windows7Reverse_1 reset")
	p.wait() 
	print "\nReset complete"

	time.sleep(540)

	print "\nShutting down Virtual Machine"
	p = subprocess.Popen("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe controlvm Windows7Reverse_1 poweroff")
	p.wait()

	time.sleep(10)
