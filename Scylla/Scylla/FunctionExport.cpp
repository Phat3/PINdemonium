#include <windows.h>
#include "PeParser.h"
#include "Scylla.h"
#include "ProcessAccessHelp.h"
#include "Architecture.h"
#include "FunctionExport.h"
#include "ProcessLister.h"
#include "ApiReader.h"
#include "IATSearch.h"
#include "ImportRebuilder.h"
#include "DllInjectionPlugin.h"
#include <fstream>
#include <string>


extern HINSTANCE hDllModule;

const WCHAR * WINAPI ScyllaVersionInformationW()
{
	return APPNAME L" " ARCHITECTURE L" " APPVERSION;
}

const char * WINAPI ScyllaVersionInformationA()
{
	return APPNAME_S " " ARCHITECTURE_S " " APPVERSION_S;
}

DWORD WINAPI ScyllaVersionInformationDword()
{
	return APPVERSIONDWORD;
}

BOOL DumpProcessW(const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
	PeParser * peFile = 0;

	if (fileToDump)
	{
		peFile = new PeParser(fileToDump, true);
	}
	else
	{
		peFile = new PeParser(imagebase, true);
	}

	return peFile->dumpProcess(imagebase, entrypoint, fileResult);
}

BOOL WINAPI ScyllaRebuildFileW(const WCHAR * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)
{

	if (createBackup)
	{
		if (!ProcessAccessHelp::createBackupFile(fileToRebuild))
		{
			return FALSE;
		}
	}

	PeParser peFile(fileToRebuild, true);
	if (peFile.readPeSectionsFromFile())
	{
		peFile.setDefaultFileAlignment();
		if (removeDosStub)
		{
			peFile.removeDosStub();
		}
		peFile.alignAllSectionHeaders();
		peFile.fixPeHeader();

		if (peFile.savePeFileToDisk(fileToRebuild))
		{
			if (updatePeHeaderChecksum)
			{
				PeParser::updatePeHeaderChecksum(fileToRebuild, (DWORD)ProcessAccessHelp::getFileSize(fileToRebuild));
			}
			return TRUE;
		}
	}

	return FALSE;
}

BOOL WINAPI ScyllaRebuildFileA(const char * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)
{
	WCHAR fileToRebuildW[MAX_PATH];
	if (MultiByteToWideChar(CP_ACP, 0, fileToRebuild, -1, fileToRebuildW, _countof(fileToRebuildW)) == 0)
	{
		return FALSE;
	}

	return ScyllaRebuildFileW(fileToRebuildW, removeDosStub, updatePeHeaderChecksum, createBackup);
}

BOOL WINAPI ScyllaDumpCurrentProcessW(const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
	ProcessAccessHelp::setCurrentProcessAsTarget();

	return DumpProcessW(fileToDump, imagebase, entrypoint, fileResult);
}

BOOL WINAPI ScyllaDumpProcessW(DWORD_PTR pid, const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
	if (ProcessAccessHelp::openProcessHandle((DWORD)pid))
	{
		return DumpProcessW(fileToDump, imagebase, entrypoint, fileResult);
	}
	else
	{
		return FALSE;
	}	
}

BOOL WINAPI ScyllaDumpCurrentProcessA(const char * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char * fileResult)
{
	WCHAR fileToDumpW[MAX_PATH];
	WCHAR fileResultW[MAX_PATH];

	if (fileResult == 0)
	{
		return FALSE;
	}

	if (MultiByteToWideChar(CP_ACP, 0, fileResult, -1, fileResultW, _countof(fileResultW)) == 0)
	{
		return FALSE;
	}

	if (fileToDump != 0)
	{
		if (MultiByteToWideChar(CP_ACP, 0, fileToDump, -1, fileToDumpW, _countof(fileToDumpW)) == 0)
		{
			return FALSE;
		}

		return ScyllaDumpCurrentProcessW(fileToDumpW, imagebase, entrypoint, fileResultW);
	}
	else
	{
		return ScyllaDumpCurrentProcessW(0, imagebase, entrypoint, fileResultW);
	}
}

BOOL WINAPI ScyllaDumpProcessA(DWORD_PTR pid, const char * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char * fileResult)
{
	WCHAR fileToDumpW[MAX_PATH];
	WCHAR fileResultW[MAX_PATH];

	if (fileResult == 0)
	{
		return FALSE;
	}

	if (MultiByteToWideChar(CP_ACP, 0, fileResult, -1, fileResultW, _countof(fileResultW)) == 0)
	{
		return FALSE;
	}

	if (fileToDump != 0)
	{
		if (MultiByteToWideChar(CP_ACP, 0, fileToDump, -1, fileToDumpW, _countof(fileToDumpW)) == 0)
		{
			return FALSE;
		}

		return ScyllaDumpProcessW(pid, fileToDumpW, imagebase, entrypoint, fileResultW);
	}
	else
	{
		return ScyllaDumpProcessW(pid, 0, imagebase, entrypoint, fileResultW);
	}
}

INT WINAPI ScyllaStartGui(DWORD dwProcessId, HINSTANCE mod)
{
	GUI_DLL_PARAMETER guiParam;
	guiParam.dwProcessId = dwProcessId;
	guiParam.mod = mod;

	return InitializeGui(hDllModule, (LPARAM)&guiParam); 
}

int WINAPI ScyllaIatSearch(DWORD dwProcessId, DWORD_PTR * iatStart, DWORD * iatSize, DWORD_PTR searchStart, BOOL advancedSearch)
{
	
	ApiReader apiReader;
	apiReader.moduleThunkList = 0;
	ProcessLister processLister;
	Process *processPtr = 0;
	IATSearch iatSearch;

	std::vector<Process>& processList = processLister.getProcessListSnapshotNative();
	for(std::vector<Process>::iterator it = processList.begin(); it != processList.end(); ++it)
	{
		if(it->PID == dwProcessId)
		{
			processPtr = &(*it);
			break;
		}
	}

	if(!processPtr) return SCY_ERROR_PIDNOTFOUND;

	ProcessAccessHelp::closeProcessHandle();
	
	apiReader.clearAll();
	if (!ProcessAccessHelp::openProcessHandle(processPtr->PID))
	{
		return SCY_ERROR_PROCOPEN;
	}

	ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);

	ProcessAccessHelp::selectedModule = 0;
	ProcessAccessHelp::targetImageBase = processPtr->imageBase;
	ProcessAccessHelp::targetSizeOfImage = processPtr->imageSize;
	apiReader.readApisFromModuleList();
	

	int retVal = SCY_ERROR_IATNOTFOUND;

	if (advancedSearch)
	{
		if (iatSearch.searchImportAddressTableInProcess(searchStart, iatStart, iatSize, true))
		{
			retVal = SCY_ERROR_SUCCESS;
		}
	}
	else
	{
		if (iatSearch.searchImportAddressTableInProcess(searchStart, iatStart, iatSize, false))
		{
			retVal = SCY_ERROR_SUCCESS;
		}
	}

	processList.clear();
	ProcessAccessHelp::closeProcessHandle();
	apiReader.clearAll();
	return retVal;
}


DWORD_PTR getNumberOfUnresolvedImports( std::map<DWORD_PTR, ImportModuleThunk> & moduleList )
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;
	std::map<DWORD_PTR, ImportThunk>::iterator iterator2;
	ImportModuleThunk * moduleThunk = 0;
	ImportThunk * importThunk = 0;
	DWORD_PTR dwNumber = 0;

	iterator1 = moduleList.begin();

	while (iterator1 != moduleList.end())
	{
		moduleThunk = &(iterator1->second);

		iterator2 = moduleThunk->thunkList.begin();

		while (iterator2 != moduleThunk->thunkList.end())
		{
			importThunk = &(iterator2->second);

			if (importThunk->valid == false)
			{
				dwNumber++;
			}

			iterator2++;
		}

		iterator1++;
	}

	return dwNumber;
}

void addUnresolvedImports( PUNRESOLVED_IMPORT firstUnresImp, std::map<DWORD_PTR, ImportModuleThunk> & moduleList )
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;
	std::map<DWORD_PTR, ImportThunk>::iterator iterator2;
	ImportModuleThunk * moduleThunk = 0;
	ImportThunk * importThunk = 0;

	iterator1 = moduleList.begin();
	
	while (iterator1 != moduleList.end())
	{
		moduleThunk = &(iterator1->second);

		iterator2 = moduleThunk->thunkList.begin();
		
		while (iterator2 != moduleThunk->thunkList.end())
		{
			importThunk = &(iterator2->second);
			
			if (importThunk->valid == false)
			{
				firstUnresImp->InvalidApiAddress = importThunk->apiAddressVA;
				firstUnresImp->ImportTableAddressPointer = importThunk->va;
				firstUnresImp++;
			}
			
			iterator2++;
		}
		
		iterator1++;
	}
	

	firstUnresImp->InvalidApiAddress = 0;
	firstUnresImp->ImportTableAddressPointer = 0;
}

void writeImportedFunctionsToFile(std::map<DWORD_PTR, ImportModuleThunk> & moduleList, const WCHAR * file_path )
{

	
	std::ofstream output_file; 
	output_file.open(file_path);

	std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;
	std::map<DWORD_PTR, ImportThunk>::iterator iterator2;
	ImportModuleThunk * moduleThunk = 0;
	ImportThunk * importThunk = 0;

	iterator1 = moduleList.begin();

	while (iterator1 != moduleList.end())
	{
		moduleThunk = &(iterator1->second);

		iterator2 = moduleThunk->thunkList.begin();

		while (iterator2 != moduleThunk->thunkList.end())
		{
			importThunk = &(iterator2->second);
			std::wstring WmoduleName(importThunk->moduleName);
			std::string  moduleName(WmoduleName.begin(),WmoduleName.end());
			std::string functionName(importThunk->name);
			output_file << moduleName << " " << functionName << "\n";
			

			iterator2++;
		}

		iterator1++;
	}
	output_file.close();

}

void displayModuleList(std::map<DWORD_PTR, ImportModuleThunk> & moduleList )
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;
	std::map<DWORD_PTR, ImportThunk>::iterator iterator2;
	ImportModuleThunk * moduleThunk = 0;
	ImportThunk * importThunk = 0;

	iterator1 = moduleList.begin();

	while (iterator1 != moduleList.end())
	{
		moduleThunk = &(iterator1->second);

		iterator2 = moduleThunk->thunkList.begin();

		while (iterator2 != moduleThunk->thunkList.end())
		{
			importThunk = &(iterator2->second);

			printf("VA : %08x\t API ADDRESS : %08x\n", importThunk->va, importThunk->apiAddressVA);
			fflush(stdout);

			iterator2++;
		}

		iterator1++;
	}

}
/*
Function which reconstruct the Import Directory of a memory dump
iatAddr: address of the IAT
iatSize: size of the IAT
dwProcessID: PID of the process from which the memory dump to fix has been taken
dumpFile: path to the dump to fix
iatFixedFile: path to the PE which will contained the Import Directory fixed
eip: Current Instruction Pointer
call_plugin_flag: flag to activate the plugin to fix the IAT
plugin_full_path: path of the plugin to fix the IAT (compulsory when call_plugin_flag is true)
reconstructed_imports_file: path to file which will contains the list of reconstructed imports
*/
int WINAPI ScyllaIatFixAutoW(DWORD_PTR iatAddr, DWORD iatSize, DWORD dwProcessId, const WCHAR * dumpFile, const WCHAR * iatFixedFile, unsigned int eip,  DWORD call_plugin_flag, const WCHAR * plugin_full_path, const WCHAR *reconstructed_imports_file)
{
	ApiReader apiReader;
	ProcessLister processLister;
	Process *processPtr = 0;

	std::map<DWORD_PTR, ImportModuleThunk> moduleList;

	std::vector<Process>& processList = processLister.getProcessListSnapshotNative();

	for(std::vector<Process>::iterator it = processList.begin(); it != processList.end(); ++it)
	{
		if(it->PID == dwProcessId)
		{
			processPtr = &(*it);					//Get the Processn which has the PID dwProcessPid
			break;
		}
	}

	if(!processPtr) return SCY_ERROR_PIDNOTFOUND;

	ProcessAccessHelp::closeProcessHandle();
	apiReader.clearAll();

	if (!ProcessAccessHelp::openProcessHandle(processPtr->PID))
	{
		return SCY_ERROR_PROCOPEN;
	}
	ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);  //In ProcessAccessHelp::moduleList List of the Dll loaded by the process and other useful information of the Process with PID equal dwProcessId
	ProcessAccessHelp::selectedModule = 0;
	ProcessAccessHelp::targetImageBase = processPtr->imageBase;
	ProcessAccessHelp::targetSizeOfImage = processPtr->imageSize;
	
	apiReader.readApisFromModuleList();		//fill the apiReader::apiList with the function exported by the dll in ProcessAccessHelp::moduleList

	apiReader.readAndParseIAT(iatAddr, iatSize, moduleList);
	//if we want the advanced iat fix technique
	if(call_plugin_flag){
		//get the number of unresolved immports based on the current module list
		DWORD_PTR numberOfUnresolvedImportsBefore = getNumberOfUnresolvedImports(moduleList);
		printf("NUMBER OF UNRES IMPORTS = %d!!!!\n", numberOfUnresolvedImportsBefore);
		//if we have some unresolved imports (IAT entry not resolved)
		printf("\n-------BEFORE:-------------\n");
		displayModuleList(moduleList);
	
		if (numberOfUnresolvedImportsBefore != 0){
			printf("Unresolved imports detected...\n");

			PUNRESOLVED_IMPORT unresolvedImport = 0;
			//allocate the structure in order to keep track of the unresolved imports
			//(numberOfUnresolvedImport +1) because we beed one last structure as end of the list
			unresolvedImport = (PUNRESOLVED_IMPORT)malloc(sizeof(UNRESOLVED_IMPORT)*(numberOfUnresolvedImportsBefore + 1));
			addUnresolvedImports(unresolvedImport, moduleList);
			
			// --------------------- LOAD AND CALL THE PLUGIN --------------------- //
			typedef UINT32 (* def_runPlugin)(static HANDLE hProcess, PUNRESOLVED_IMPORT unresolvedImport, unsigned int eip);
			//load the dll
			HMODULE pluginDll = 0;
			LPCWSTR path = plugin_full_path;
			//load library
			pluginDll = LoadLibraryEx(path, NULL, NULL);
			def_runPlugin runPlugin;
			//get proc address
			if (pluginDll)
			{
				runPlugin = (def_runPlugin)GetProcAddress(pluginDll, "runPlugin");
				//call the plugin
				runPlugin(ProcessAccessHelp::hProcess, unresolvedImport, eip);
			}
			else{
				printf("\n\n!!!ERROR WHILE LOADING PLUGIN!!!\n\n");
			}

			FreeLibrary(pluginDll);

			// --------------------- END LOAD AND CALL THE PLUGIN --------------------- //

			apiReader.clearAll();

			//moduleList.clear();

			ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);

			apiReader.readApisFromModuleList();

			apiReader.readAndParseIAT(iatAddr, iatSize, moduleList);
		
		}

		printf("\n-------AFTER:-------------\n");
		DWORD_PTR numberOfUnresolvedImportsAfter = getNumberOfUnresolvedImports(moduleList);
		printf("NUMBER OF UNRES IMPORTS = %d!!!!\n", numberOfUnresolvedImportsAfter);
		displayModuleList(moduleList);
		if(numberOfUnresolvedImportsBefore == numberOfUnresolvedImportsAfter && numberOfUnresolvedImportsBefore != 0){
			return SCY_ERROR_IATWRITE;
		}
	
	}
	//write imported function reconstructed to file
	writeImportedFunctionsToFile(moduleList,reconstructed_imports_file);
	//add IAT section to dump
	ImportRebuilder importRebuild(dumpFile);

	importRebuild.enableOFTSupport();

	int retVal = SCY_ERROR_IATWRITE;

	if (importRebuild.rebuildImportTable(iatFixedFile, moduleList))
	{	
		retVal = SCY_ERROR_SUCCESS;
	}

	processList.clear();

	moduleList.clear();
	ProcessAccessHelp::closeProcessHandle();
		
	apiReader.clearAll();

	return retVal;
}


/* ADDED FROM OUR TEAM */

int WINAPI ScyllaAddSection(const WCHAR * dump_path , const CHAR * sectionName, DWORD sectionSize, UINT32 offset, BYTE * sectionData){
	
	PeParser * peFile = 0;

	// open the dumped file 
	if (dump_path)
	{
		peFile = new PeParser(dump_path, TRUE);
	}

	// read the data inside all the section from the PE in order to left unchanged the dumped PE 
	peFile->readPeSectionsFromFile();

	// add a new last section
	bool res = peFile->addNewLastSection(sectionName, sectionSize, sectionData);

	// fix the PE file 
	peFile->alignAllSectionHeaders();
	peFile->setDefaultFileAlignment();
	peFile->fixPeHeader();
	
	// get the last inserted section in order to retreive the VA 
	PeFileSection last_section = peFile->getSectionHeaderList().back();
	IMAGE_SECTION_HEADER last_section_header = last_section.sectionHeader;
	UINT32 last_section_header_va = last_section_header.VirtualAddress;

	// set the entry point of the dumped program to the .heap section 
	peFile->setEntryPointVa(last_section_header_va + offset );
	
	// save the pe

	return peFile->savePeFileToDisk(dump_path);
	
	//return 1;
	
}

