# PINdemonium
An unpacker for windows executables exploiting the capabilities of PIN.

## Dependencies

* [PIN](http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-msvc10-windows.zip)

* [Scylla](https://github.com/NtQuery/Scylla) 

* Visual studio 2010

* IDAPro 6.6


## Installation

1. Download the linked version of PIN

2. Unzip PIN to the root directory and rename the folder to **pin**

3. Clone this repository

4. Extract the archive in PINdemonium/ScyllaDependencies/diStorm.rar into PINdemonium/Scylla/

5. Extract the archive in PINdemonium/ScyllaDependencies/tinyxml.rar into PINdemonium/Scylla/

6. Extract the archive in PINdemonium/ScyllaDependencies/WTL.rar into PINdemonium/Scylla/WTL/ 

5. Open the file **PinUnpacker.sln** with Visual Studio 2010 ( **NB: The version is mandatory** )

5. Set your IDAPro (idaw.exe) path in **Config.cpp** ( const **Log::IDA_PATH** )

6. Copy the folders **PINdemonium\PINdemoniumDependencies** and **PINdemonium\PINdemoniumResults** in **C:\pin\\**

7. Be sure that you are compiling in Release mode 

8. Be sure that all the module inside the project are compiled using the platform toolset v100 ( you can see this with right click on the module -> Properties -> platform toolset field )

9. Compile the solution

```
	\---C
	    \---pin
			   \+---source
			   	| 	     
			   	|
			   	|
			   \+---PINdemoniumResults
			   	|
			   	|
			   	|
			   	|
			   \+---PINdemoniumDependencies 
			   	|						  \---badImportsChecker.py
			   	|			              \---badImportsList.txt
			   	|						  \---dumperSelector.py
			   	|						  \---Scylla
			   	|								\---ScyllaDLLRelease
			   	|									\---ScyllaDLLx86.dll
			   	|								\---ScyllaDLLDebug
			   	|									\---ScyllaDLLx86.dll
			   	|								\---ScyllaDumper.exe
			   	|
			   \+---PINdemonium.dll
```

## Usage

1. Run this command from the directory **C:\pin\\**

	```
	pin -t PINdemonium.dll [-flags] -- <path_to_the_exe_to_be_instrumented>
	```

	**Flags :**
	- **-iwae <number_of_jump_to_dump>** : specify if you want or not to track the inter_write_set analysis dumps and how many jump
	

	- **-adv-iatfix** : specify if you want or not to activate the advanced IAT fix technique
	

	- **-poly-patch**: if the binary you are analyzing has some kind of polymorphic behavior this activate the patch in order to avoid pin to execute the wrong trace.


	- **-nullify-unk-iat**: specify if you want or not to nullify the IAT entry not detected as correct API by the tool. NB: THIS OPTION WORKS ONLY IF THE OPTION adv-iatfix IS ACTIVE!


2. Check your result in **C:\pin\PINdemoniumResults\\< current_date_and_time >\\**
