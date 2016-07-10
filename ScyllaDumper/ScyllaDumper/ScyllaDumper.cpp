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


UINT32 IATAutoFix(DWORD pid, DWORD_PTR oep, WCHAR *outputFile, WCHAR* tmpDumpFile, DWORD call_plugin_flag, WCHAR *plugin_full_path, WCHAR *reconstructed_imports_file);
BOOL GetFilePathFromPID(DWORD dwProcessId, WCHAR *filename);
DWORD_PTR GetExeModuleBase(DWORD dwProcessId);



HMODULE hScylla = 0;


//
// arg 1 : Pid
// arg 2 : Original entry poiunt
// arg 3 : Output file path
// arg 4 : Tmp file path used by scylla 
// arg 5 : Full path of the file where the resolved imports will be written 
// arg 6 : Call plugin flag --> 0 don't call any plugin, 1 --> call the plugin pointed by plugin_full_path
// arg 7 : Full path of the dll containing the plugin that has to be called
int wmain(int argc, wchar_t *argv[]){
	
	if(argc < 6){
		INFO("ScyllaTest.exe <pid> <oep> <output_file> <tmp_dump>  <reconstructed_imports_file> <call_plugin_flag> <plugin_full_path>");
		return -1;
	}
	//INFO("argv0 %S argv1 %S argv2 %S argv3 %S argv4 %S argv5 %S argv6 %S arg7  %S", argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
	DWORD pid = _wtoi(argv[1]);
	DWORD_PTR oep = wcstoul(argv[2],NULL,16);
	WCHAR *outputFile = argv[3];
	WCHAR *tmpDumpFile = argv[4];
	WCHAR *reconstructed_imports_file = argv[5];
	DWORD call_plugin_flag = _wtoi(argv[6]);
	WCHAR *plugin_full_path = argv[7]; // need to be left as last parameter since it can be empty
	
	return IATAutoFix(pid, oep, outputFile, tmpDumpFile, call_plugin_flag, plugin_full_path,reconstructed_imports_file);
	
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



UINT32 IATAutoFix(DWORD pid, DWORD_PTR oep, WCHAR *outputFile, WCHAR *tmpDumpFile, DWORD call_plugin_flag, WCHAR *plugin_full_path, WCHAR *reconstructed_imports_file)
{

	DWORD_PTR iatStart = 0;
	DWORD iatSize = 0;
	WCHAR originalExe[MAX_PATH]; // Path of the original PE which as launched the current process

	//getting the Base Address
	DWORD_PTR hMod = GetExeModuleBase(pid);
	if(!hMod){
		INFO("Can't find PID");
	}
	
	//INFO("GetExeModuleBase %X", hMod);

	//Dumping Process
	BOOL success = GetFilePathFromPID(pid,originalExe);
	if(!success){
		INFO("Error in getting original Path from Pid: %d",pid);
		return SCYLLA_ERROR_FILE_FROM_PID;
	}
	
	//INFO("Original Exe Path: %S",originalExe);
		
	success = ScyllaDumpProcessW(pid,originalExe,hMod,oep,tmpDumpFile);
	if(!success){
		INFO("[SCYLLA DUMP] Error Dumping  Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S ",pid,originalExe,hMod,oep,tmpDumpFile);
		return SCYLLA_ERROR_DUMP;
	}
	INFO("[SCYLLA DUMP] Successfully dumped Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S ",pid,originalExe,hMod,oep,tmpDumpFile);

	INFO("[SCYLLA DUMP] Now let's search the IAT!\n");
	INFO("[SCYLLA SEARCH] (1) Trying with the advanced IAT search\n");
	//Searching the IAT
	int basic_iat_search_error = 0;
	int adv_iat_search_error = ScyllaIatSearch(pid, &iatStart, &iatSize, oep, TRUE);
	int iat_fix_error = 0;
	//check if ScyllaIATSearch failed and if the result IAT address is readable	
	if(adv_iat_search_error || !isMemoryReadable(pid, (void *) iatStart, iatSize)){
		// display error 
		if(adv_iat_search_error){  
			ERRORE("[SCYLLA ADVANCED SEARCH] error %d \n", adv_iat_search_error); 
		}
		else{
			ERRORE("[SCYLLA ADVANCED SEARCH] IAT address not readable/mapped iat_start : %08x\t iat_size : %08x\n", iatStart, iatSize);
		}
		INFO("[SCYLLA SEARCH] (2) Trying basic IAT search");
		//Trying  Basic IAT search
		basic_iat_search_error = ScyllaIatSearch(pid, &iatStart, &iatSize, oep, FALSE);
		if(basic_iat_search_error || !isMemoryReadable(pid, (void *) iatStart,iatSize)){
			if(basic_iat_search_error){  
				ERRORE("[SCYLLA BASIC SEARCH] error %d\n",basic_iat_search_error); 
			}
			else{
				ERRORE("[SCYLLA BASIC SEARCH] IAT address  not readable/mapped iat_start : %08x\t iat_size : %08x\n",iatStart,iatSize);
			}
			return SCYLLA_ERROR_IAT_NOT_FOUND;
		}
	}
	INFO("[SCYLLA SEARCH] iat_start : %08x\t iat_size : %08x\t pid : %d\n", iatStart,iatSize,pid,outputFile);	
	//Fixing the IAT
	iat_fix_error = ScyllaIatFixAutoW(iatStart,iatSize,pid,tmpDumpFile,outputFile, oep, call_plugin_flag, plugin_full_path,reconstructed_imports_file);
	if(iat_fix_error){
		INFO("[SCYLLA FIX] error %d\n",iat_fix_error);
		INFO("[SCYLLA SEARCH] Trying basic IAT search");
		//Trying  Basic IAT search
		basic_iat_search_error = ScyllaIatSearch(pid, &iatStart, &iatSize, oep, FALSE);
		if(basic_iat_search_error || !isMemoryReadable(pid, (void *) iatStart,iatSize)){
			if(basic_iat_search_error){  
				ERRORE("[SCYLLA BASIC SEARCH] error %d\n",basic_iat_search_error); 
			}
			else{
				ERRORE("[SCYLLA BASIC SEARCH] IAT address  not readable/mapped iat_start : %08x\t iat_size : %08x\n",iatStart,iatSize);
			}
			return SCYLLA_ERROR_IAT_NOT_FOUND;
		}
		else{
			iat_fix_error = ScyllaIatFixAutoW(iatStart,iatSize,pid,tmpDumpFile,outputFile, oep, call_plugin_flag, plugin_full_path,reconstructed_imports_file);
			if(iat_fix_error){
				INFO("[SCYLLA FIX] error %d\n",iat_fix_error);
				return SCYLLA_ERROR_IAT_NOT_FIXED;
			}
		}
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


