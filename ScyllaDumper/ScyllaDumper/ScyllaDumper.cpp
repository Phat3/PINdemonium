// ScyllaTest.cpp : definisce il punto di ingresso dell'applicazione console.
//

#include "stdafx.h"
#include "debug.h"
#include "Log.h"
#include "FunctionExport.h"

#define SCYLLA_DLL_DEBUG

#define SCYLLA_ERROR_FILE_FROM_PID -4
#define SCYLLA_ERROR_DUMP -3
#define SCYLLA_ERROR_IAT_NOT_FOUND -2
#define SCYLLA_ERROR_IAT_NOT_FIXED -1
#define SCYLLA_SUCCESS_FIX 0


UINT32 IATAutoFix(DWORD pid, DWORD_PTR oep, WCHAR *outputFile, DWORD advance_iat_fix_flag, WCHAR* tmpDumpFile);
BOOL GetFilePathFromPID(DWORD dwProcessId, WCHAR *filename);
DWORD_PTR GetExeModuleBase(DWORD dwProcessId);



HMODULE hScylla = 0;



int wmain(int argc, wchar_t *argv[]){

	
	if(argc < 4){
		INFO("ScyllaTest.exe <pid> <oep> <output_file> <advance_iat_fix_flag> <tmp_dump");
		return -1;
	}
	INFO("argv0 %S argv1 %S argv2 %S argv3 %S argv4 %S", argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]);
	DWORD pid = _wtoi(argv[1]);
	// DWORD_PTR oep  = _wtoi(argv[2]);// Works if passed and integer base 10 value
	DWORD_PTR oep = wcstoul(argv[2],NULL,16);
	WCHAR *outputFile = argv[3];
	DWORD advance_iat_fix_flag = _wtoi(argv[4]);
	WCHAR *tmpDumpFile = argv[5];
	//DebugBreak();
	return IATAutoFix(pid, oep, outputFile, advance_iat_fix_flag, tmpDumpFile);
	
}




BOOL isMemoryReadable(DWORD pid, void *ptr, size_t byteCount)
{
  MEMORY_BASIC_INFORMATION mbi;
  HANDLE hProcess = 0;
  hProcess =  OpenProcess(PROCESS_VM_OPERATION|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, 0, pid);
  if(hProcess){
	  if (VirtualQueryEx(hProcess, ptr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
		return false;

	  if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS)
		return false;

	  return true;
  }
  return false;
}




UINT32 IATAutoFix(DWORD pid, DWORD_PTR oep, WCHAR *outputFile, DWORD advance_iat_fix_flag, WCHAR *tmpDumpFile)
{

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
		
	success = ScyllaDumpProcessW(pid,originalExe,hMod,oep,tmpDumpFile);
	if(!success){
		INFO("[SCYLLA DUMP] Error Dumping  Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S ",pid,originalExe,hMod,oep,tmpDumpFile);
		return SCYLLA_ERROR_DUMP;
	}
	INFO("[SCYLLA DUMP] Successfully dumped Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S ",pid,originalExe,hMod,oep,tmpDumpFile);
		
	//DebugBreak();
	//Searching the IAT
	int error = ScyllaIatSearch(pid, &iatStart, &iatSize, hMod + 0x00001028, TRUE);

	//check if ScyllaIATSearch failed and if the result IAT address is readable
	
	if(error || !isMemoryReadable(pid, (void *) iatStart,iatSize)){

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
		if(error2 || !isMemoryReadable(pid, (void *) iatStart,iatSize)){

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
	//DebugBreak();
	error = ScyllaIatFixAutoW(iatStart,iatSize,pid,tmpDumpFile,outputFile,advance_iat_fix_flag, oep);
	if(error){
		INFO("[SCYLLA FIX] error %d",error);
		return SCYLLA_ERROR_IAT_NOT_FIXED;
	}

	//Removing the correct dump from the not working directory
	_wremove(tmpDumpFile);

	INFO("[SCYLLA FIX] Success fixed file at %S",outputFile);
	return SCYLLA_SUCCESS_FIX;
	
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
		ERRORE("Failed to get module filename.\n");
		return false;
	}
	CloseHandle(processHandle);
	} else {
		ERRORE("Failed to open process.\n" );
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


