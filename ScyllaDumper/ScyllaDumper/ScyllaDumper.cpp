// ScyllaTest.cpp : definisce il punto di ingresso dell'applicazione console.
//

#include "stdafx.h"
#include "debug.h"
#include "Log.h"

#define SCYLLA_DLL_DEBUG

#ifdef SCYLLA_DLL_DEBUG
#define SCYLLA_DLL L"./ScyllaDllDebug/ScyllaDLLx86.dll"
#else
#define SCYLLA_DLL L"./ScyllaDllRelease/ScyllaDLLx86.dll"
#endif





typedef int (WINAPI * def_ScyllaIatSearch)(DWORD dwProcessId, DWORD_PTR * iatStart, DWORD * iatSize, DWORD_PTR searchStart, BOOL advancedSearch);
typedef int  (WINAPI * def_ScyllaIatFixAutoW)(DWORD_PTR iatAddr, DWORD iatSize, DWORD dwProcessId, const WCHAR * dumpFile, const WCHAR * iatFixFile);
typedef BOOL (WINAPI * def_ScyllaDumpProcessW)(DWORD_PTR pid, const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult);

	 
def_ScyllaIatSearch ScyllaIatSearch = 0;
def_ScyllaIatFixAutoW  ScyllaIatFixAutoW = 0;
def_ScyllaDumpProcessW  ScyllaDumpProcessW = 0;


void IATAutoFix(DWORD pid, DWORD_PTR oep, WCHAR *outputFile);
BOOL GetFilePathFromPID(DWORD dwProcessId, WCHAR *filename);
DWORD_PTR GetExeModuleBase(DWORD dwProcessId);



HMODULE hScylla = 0;

/**
Load Scylla library from dll and importing usefull functions
**/
void LoadScyllaLibrary(){
	#ifdef _WIN64
		hScylla = LoadLibraryW(L"./ScyllaDLLx64.dll");
	#else
		hScylla = LoadLibraryW(SCYLLA_DLL);
	#endif
		INFO("Loading scylla\n ");
		if (hScylla)
		{
			ScyllaIatSearch = (def_ScyllaIatSearch)GetProcAddress(hScylla, "ScyllaIatSearch");
			ScyllaIatFixAutoW = (def_ScyllaIatFixAutoW)GetProcAddress(hScylla, "ScyllaIatFixAutoW");
			ScyllaDumpProcessW = (def_ScyllaDumpProcessW)GetProcAddress(hScylla, "ScyllaDumpProcessW");
		}

}

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
	//Loading Scylla Functions
	LoadScyllaLibrary();
	IATAutoFix(pid, oep, outputFile);
	return 0;
}








void IATAutoFix(DWORD pid, DWORD_PTR oep, WCHAR *outputFile)
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
		return;
	}
	INFO("Original Exe Path: %S\n",originalExe);
		
	success = ScyllaDumpProcessW(pid,originalExe,hMod,oep,dumpFile);
	if(!success){
		ERRORE("Error Dumping  Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S \n",pid,originalExe,hMod,oep,dumpFile);
		return;
	}
	INFO("Successfully dumped Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S \n",pid,originalExe,hMod,oep,dumpFile);
		
	
	
	//Searching the IAT
	int error = ScyllaIatSearch(pid, &iatStart, &iatSize, hMod + 0x00001028, TRUE);
	if(error){
		ERRORE("(IAT SEARCH) error %d \n",error);
		return;
	}
	INFO("(IAT SEARCH) iatStart %X iatSize %X\n",iatStart, iatSize);
	

	//Fixing the IAT
	error = ScyllaIatFixAutoW(iatStart,iatSize,pid,dumpFile,outputFile);
	if(error){
		ERRORE("(IAT FIX) error %d",error);
		return;
	}
	INFO("[IAT FIX] Success");
	
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


