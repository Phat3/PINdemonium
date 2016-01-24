// ScyllaWrapper.cpp: definisce le funzioni esportate per l'applicazione DLL.
//

#pragma once
#include "stdafx.h"
#include "ScyllaWrapper.h"
#include "debug.h"
#include "Log.h"

#define SCYLLA_ERROR_FILE_FROM_PID -4
#define SCYLLA_ERROR_DUMP -3
#define SCYLLA_ERROR_IAT_NOT_FOUND -2
#define SCYLLA_ERROR_IAT_NOT_FIXED -1
#define SCYLLA_SUCCESS_FIX 0

void SetCurrentLogDirectory(const CHAR * currentPath){
	
}

/**
Extract the .EXE file which has lauched the process having PID pid
**/
BOOL GetFilePathFromPID(DWORD dwProcessId, WCHAR *filename){
	
	HANDLE processHandle = NULL;

	processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
	if (processHandle) {
		if (GetModuleFileNameEx(processHandle,NULL, filename, MAX_PATH) == 0) {
		//if (GetProcessImageFileName(processHandle, filename, MAX_PATH) == 0) {
			INFO("Failed to get module filename.");
			return false;
		}
		CloseHandle(processHandle);
	} else {
		INFO("Failed to open process." );
		return false;
	}

	return true;
}


DWORD_PTR GetExeModuleBase(DWORD dwProcessId)
{
	MODULEENTRY32 lpModuleEntry = { 0 };
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	lpModuleEntry.dwSize = sizeof(lpModuleEntry);
	Module32First(hSnapShot, &lpModuleEntry);

	CloseHandle(hSnapShot);

	return (DWORD_PTR)lpModuleEntry.modBaseAddr;
}

BOOL isMemoryReadable(void *ptr, size_t byteCount)
{
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(ptr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
    return false;

  if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS)
    return false;

  return true;
}


UINT32 IATAutoFix(DWORD pid, DWORD_PTR oep, WCHAR *outputFile, WCHAR * cur_path, WCHAR * tmp_dump)
{

	Log::getInstance()->initLogPath(cur_path);//Initialize the log File NEED TO BE BEFORE ANY INFO(),WARN(),ERROR()


	PRINT("\n\n-------------------------------------------------------------------------------------------------------");
	PRINT("------------------------------------ IAT Fixing at %08x -------------------------------------",oep);
	PRINT("-------------------------------------------------------------------------------------------------------");

	DWORD_PTR iatStart = 0;
	DWORD iatSize = 0;
	WCHAR originalExe[MAX_PATH]; // Path of the original PE which as launched the current process

	//getting the Base Address
	DWORD_PTR hMod = GetExeModuleBase(pid);
	if(!hMod){
		INFO("Can't find PID");
	}
	INFO("GetExeModuleBase %X", hMod);

	//Dumping Process
	BOOL success = GetFilePathFromPID(pid,originalExe);
	if(!success){
		INFO("Error in getting original Path from Pid: %d",pid);
		return SCYLLA_ERROR_FILE_FROM_PID;
	}
	INFO("Original Exe Path: %S",originalExe);
		
	success = ScyllaDumpProcessW(pid,originalExe,hMod,oep,tmp_dump);
	if(!success){
		INFO("[SCYLLA DUMP] Error Dumping  Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S ",pid,originalExe,hMod,oep,tmp_dump);
		return SCYLLA_ERROR_DUMP;
	}
	INFO("[SCYLLA DUMP] Successfully dumped Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S ",pid,originalExe,hMod,oep,tmp_dump);
		
	//DebugBreak();
	//Searching the IAT
	int error = ScyllaIatSearch(pid, &iatStart, &iatSize, hMod + 0x00001028, TRUE);

	//check if ScyllaIATSearch failed and if the result IAT address is readable

	if(error || !isMemoryReadable((void *) iatStart,iatSize)){

		/*Display why the Scylla IAT Search failed: 
			- error in IAT search
			- address found not readable */
		if(error){  
			ERRORE("[SCYLLA ADVANCED SEARCH] error %d  ",error); 
		}
		else{
				ERRORE("[SCYLLA ADVANCED SEARCH] IAT address not readable/mapped iat_start : %08x\t iat_size : %08x\t  ",iatStart,iatSize);
		}
		
		INFO("[SCYLLA SEARCH] Trying basic IAT search");

		//Trying  Basic IAT search
		int error2 = ScyllaIatSearch(pid, &iatStart, &iatSize, hMod + 0x00001028, FALSE);
		if(error2  || !isMemoryReadable((void *) iatStart,iatSize)){

			/*Display why the Scylla IAT Search failed: 
			 - error in IAT search
			 - address found not readable */
			if(error2){  
				ERRORE("[SCYLLA BASIC SEARCH] error %d  ",error2); 
			}
			else{
				 ERRORE("[SCYLLA BASIC SEARCH] IAT address  not readable/mapped iat_start : %08x\t iat_size : %08x\t ",iatStart,iatSize);
			}
			return SCYLLA_ERROR_IAT_NOT_FOUND;
		}
	}

	INFO("[SCYLLA SEARCH] iat_start : %08x\t iat_size : %08x\t pid : %d", iatStart,iatSize,pid,outputFile);
	
	//Fixing the IAT
	error = ScyllaIatFixAutoW(iatStart,iatSize,pid,tmp_dump,outputFile);
	if(error){
		INFO("[SCYLLA FIX] error %d",error);
		return SCYLLA_ERROR_IAT_NOT_FIXED;
	}

	//Removing the correct dump from the not working directory
	_wremove(tmp_dump);

	INFO("[SCYLLA FIX] Success fixed file at %S",outputFile);
	return SCYLLA_SUCCESS_FIX;
	
}


UINT32 ScyllaDumpAndFix(int pid, int oep, WCHAR * output_file, WCHAR * cur_path, WCHAR * tmp_dump){
	return IATAutoFix(pid, oep, output_file, cur_path, tmp_dump);
}


UINT32 ScyllaWrapAddSection(const WCHAR * dump_path , const CHAR * sectionName, DWORD sectionSize, UINT32 offset, BYTE * sectionData){
	return ScyllaAddSection(dump_path , sectionName, sectionSize, offset , sectionData);
}



