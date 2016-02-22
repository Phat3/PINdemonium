# Pin unpacking and anti-evasion

## Dependencies

* [PIN](http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-msvc10-windows.zip)

* [Scylla](https://github.com/NtQuery/Scylla) 

* Visual studio 2010

* IDAPro 6.6


## Installation

1. Download the linked version of PIN

2. Unzip PIN to the root directory and rename the folder to **pin**

3. Clone this repository

4. Extract the archive in FindOEPPin/ScyllaDependencies/diStorm.rar into FindOEPPin/Scylla/

5. Extract the archive in FindOEPPin/ScyllaDependencies/tinyxml.rar into FindOEPPin/Scylla/

6. Extract the archive in FindoEPPin/ScyllaDependencies/WTL.rar into FindoOEPPin/Scylla/WTL/ 

5. Open the file **PinUnpacker.sln** with Visual Studio 2010 ( **NB: The version is mandatory** )

5. Set your IDAPro path in **Config.cpp** ( const **Log::IDA_PATH** )

6. Copy the folders **FindOEPPin\PinUnpackerDependencies** and **FindOEPPin\PinUnpackerResults** in **C:\pin\\**

7. Be sure that you are compiling in Release mode 

8. Be sure that all the module inside the project are compiled using the platform toolset v100 ( you can see this with right click on the module -> Propreties -> platform toolset field )

9. Compile the solution

```
	\---C
	    \---pin
			   \+---source
			   	| 	     
			   	|
			   	|
			   \+---PinUnpackerResults
			   	|
			   	|
			   	|
			   	|
			   \+---PinUnpackerDependencies 
			   	|						  \---badImportsChecker.py
			   	|			              \---badImportsList.txt
			   	|						  \---dumperSelector.py
			   	|						  \---Scylla
			   	|								\---ScyllaDLLRelease
			   	|								\---ScyllaDLLDebug
			   	|								\---ScyllaDumper.exe
			   	|
			   \+---FindOEPPin.dll
```

## Usage

1. Run this command from the directory **C:\pin\\**

	```
	pin -t FindOEPPin.dll [-flags] -- <path_to_the_exe_to_be_instrumented>
	```

	**Flags :**
	- **iwae number_of_jump_to_dump** : specify if you want or not to track the inter_write_set analysis dumps and how many jump


	- **antiev** : specify if you want or not to activate the anti evasion engine


	- **antiev-ins** : specify if you want or not to activate the single patching of evasive instruction as int2e, fsave...


	- **antiev-sread** : specify if you want or not to activate the handling of suspicious reads


	- **antiev-swrite** : specify if you want or not to activate the handling of suspicious writes


	- **unp** : specify if you want or not to activate the unpacking engine


	- **adv-iatfix** : specify if you want or not to activate the advanced IAT fix technique


2. Check your result in **C:\pin\PinUnpackerResults\\< current_date_and_time >\\**
