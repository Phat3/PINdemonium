# PINdemonium
An unpacker for windows executables exploiting the capabilities of PIN.

## Dependencies

* [PIN](http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-msvc10-windows.zip)

* [Scylla](https://github.com/NtQuery/Scylla) 

* Visual studio 2010



## Installation

1. Download the linked version of PIN

2. Unzip PIN to the root directory and rename the folder to **pin**

3. Clone this repository

4. Extract the archive in PINdemonium/ScyllaDependencies/diStorm.rar into PINdemonium/Scylla/

5. Extract the archive in PINdemonium/ScyllaDependencies/tinyxml.rar into PINdemonium/Scylla/

6. Extract the archive in PINdemonium/ScyllaDependencies/WTL.rar into PINdemonium/Scylla/

5. Open the file **PinUnpacker.sln** with Visual Studio 2010 ( **NB: The version is mandatory** )

6. Create a folder C:\\pin and copy the folders **PINdemonium\PINdemoniumDependencies** and **PINdemonium\PINdemoniumResults** in **C:\pin\\**

7. Be sure that you are compiling in Release mode 

8. Be sure that all the module inside the project are compiled using the platform toolset v100 ( you can see this with right click on the module -> Properties -> platform toolset field )

9. Compile the solution

10. **Optional** : Create a folder called **PINdemoniumPlugins** in **C:\pin\\**

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
			   	|						  
			   	|			              	\---config.json
			   	|					\---Yara
			   	|								\--yara_rules.yar
			   	|								\--rules
			   	|					\---Scylla
			   	|								\---ScyllaDLLRelease
			   	|									\---ScyllaDLLx86.dll
			   	|								\---ScyllaDLLDebug
			   	|									\---ScyllaDLLx86.dll
			   	|								\---ScyllaDumper.exe
			   	|
			   	|
			   	|
			   \+---PINdemoniumPlugins
			   	|
			   	|
			   	|
			   	|
			   \+---PINdemonium.dll
```

## Usage

1. Run this command from the directory **C:\pin\\**

	```
	pin -t PINdemonium.dll [-flags] -- <path_to_the_exe_to_be_instrumented>s
	```

	**Flags :**
	- **-iwae <number_of_jump_to_dump>** : specify if you want or not to track the inter_write_set analysis dumps and how many jump
		

	- **-poly-patch**: if the binary you are analyzing has some kind of polymorphic behavior this activate the patch in order to avoid pin to execute the wrong trace.


	- **-plugin <name_of_the_plugin>**: specify if you want to call a custom plugin if the IAT-fix fails (more information on in the Plugin system section).

2. Check your result in **C:\pin\PINdemoniumResults\\< current_date_and_time >\\**

## Plugin System
PINdemonium provides a plugin system in order to extend the functionalities of the IAT fixing module.

To write your own plugin you have to:

1. Copy the sample project called **PINdemoniumPluginTemplate** located in **PINdemonium\PINdemoniumPlugins\\**  wherever you want.

2. Change the name of the project with a name of your choice

3. Implement the function **runPlugin**

4. Compile the project

5. Copy the compiled Dll in **C:\pin\PINdemoniumPlugins**

6. Launch PINdemonium with the flag **plugin** active followed by your plugin name (EX : -plugin PINdemoniumStolenAPIPlugin.dll)

Inside the template two helper function are provided:

- **readMemoryFromProcess** : this function reads the memory from the specified process, at the specified address and copies the read bytes into a buffer

- **writeMemoryToProcess** : this function writes the bytes contained inside a specified buffer into the process memory starting from a specified address
## Yara Rules
Every time a dump is taken yara is invoked and the rules contained inside C:\pin\PINdemoniumDependencies\Yara\yara_rules.yar are checked. The current rule comes from https://github.com/Yara-Rules/rules:
	- rules\evasion_packer : Try to identify antiVM/antiDebug techniques and the presence of a known packer
	- rules\malware: Try to identify the malware family of the unpacked stage
## Config
Config file located at C:\pin\PINdemoniumDependencies\config.json contains variables which allow to set the location of the outputs

## Results
Results are located at **C:\pin\PINdemoniumResults\\< current_date_and_time >\\** and contains:
	- **report_PINdemonium**: Json file which contains the most important information about the unpacking process;
	- **log_PINdemonium.txt**: Log which contains useful debugging information
### Report Structure
```json
{  
   "dumps":[                                   		#Array containing information for each dump
      {  
         "eip":4220719,         			#EIP where the dump was taken     
         "start_address":4220439,			#start address of the Write-set block
         "end_address":4221043,				#end address of the Write-set block
         "heuristics":[
            {						#Yara Rules Heuristic
               "matched_rules":["ASProtectv12AlexeySolodovnikovh1"],
                "name":"YaraRulesHeuristic",
                "result":true
            },
            {  
               "length":1801,				#Long Jump Heuristic
               "name":"LongJumpHeuristic",
               "prev_ip":4218918,
               "result":true
            },
            {  
               "current_entropy":5.7026081085205078,    #Entropy Heuristic
               "difference_entropy_percentage":0.0014407391427084804,
               "name":"EntropyHeuristic",
               "result":false
            },
            {  
               "current_section":".data",		#Jump Outer Section Heuristic
               "name":"JumpOuterSectionHeuristic",
               "prev_section":".data",
               "result":false
            }
         ],
         "imports":[  
		.... Imported functions....
         ],
         "intra_writeset":false,
         "number":0,
         "reconstructed_imports":0
       
      },
   ]
}
```

