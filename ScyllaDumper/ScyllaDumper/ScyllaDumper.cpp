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


UINT32 IATAutoFix(DWORD pid, DWORD_PTR oep, WCHAR *outputFile);
BOOL GetFilePathFromPID(DWORD dwProcessId, WCHAR *filename);
DWORD_PTR GetExeModuleBase(DWORD dwProcessId);



HMODULE hScylla = 0;



int wmain(int argc, wchar_t *argv[]){

	
	if(argc < 4){
		INFO("ScyllaTest.exe <pid> <oep> <output_file>");
		return -1;
	}
	INFO("argv0 %S argv1 %S argv2 %S argv3 %S",argv[0],argv[1],argv[2],argv[3]);
	DWORD pid = _wtoi(argv[1]);
	// DWORD_PTR oep  = _wtoi(argv[2]);// Works if passed and integer base 10 value
	DWORD_PTR oep = wcstoul(argv[2],NULL,16);
	
	WCHAR *outputFile = argv[3];
	return IATAutoFix(pid, oep, outputFile);
	
}








UINT32 IATAutoFix(DWORD pid, DWORD_PTR oep, WCHAR *outputFile)
{
	INFO("----------------IAT Fixing Test----------------\n");

	
	DWORD_PTR iatStart = 0;
	DWORD iatSize = 0;
	WCHAR originalExe[MAX_PATH]; // Path of the original PE which as launched the current process
	WCHAR *dumpFile = L"./tmp_dump_file.exe";  //Path of the file where the process will be dumped during the Dumping Process
	
	//getting the Base Address
	DWORD_PTR hMod = GetExeModuleBase(pid);
	if(!hMod){
		DEBUG("Can't find PID");
	}
	INFO("GetExeModuleBase %X\n", hMod);

	

	//Dumping Process
	BOOL success = GetFilePathFromPID(pid,originalExe);
	if(!success){
		ERRORE("Error in getting original Path from Pid: %d\n",pid);
		return SCYLLA_ERROR_FILE_FROM_PID;
	}
	INFO("Original Exe Path: %S\n",originalExe);
	
	/* hMod is the reference to the ExE module base */
	success = ScyllaDumpProcessW(pid,originalExe,hMod,oep,dumpFile);
	if(!success){
		ERRORE("Error Dumping  Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S \n",pid,originalExe,hMod,oep,dumpFile);
		return SCYLLA_ERROR_DUMP;
	}
	INFO("Successfully dumped Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S \n",pid,originalExe,hMod,oep,dumpFile);
		
	//DebugBreak();
	//Searching the IAT
	int error = ScyllaIatSearch(pid, &iatStart, &iatSize, hMod + 0x00001028, TRUE);
	if(error){
		ERRORE("(IAT SEARCH) error %d \n",error);
		return SCYLLA_ERROR_IAT_NOT_FOUND;
	}
	INFO("(IAT SEARCH) iatStart %X iatSize %X\n",iatStart, iatSize);
	
	
	//Fixing the IAT
	INFO("\n\n\n\nFIXING ...... start : %08x\t size : %08x\t pid : %d\t output : %s\n\n\n\n", iatStart,iatSize,pid,dumpFile,outputFile);

	error = ScyllaIatFixAutoW(iatStart,iatSize,pid,dumpFile,outputFile);
	if(error){
		ERRORE("(IAT FIX) error %d",error);
		return SCYLLA_ERROR_IAT_NOT_FIXED;
	}
	INFO("[IAT FIX] Success");
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


