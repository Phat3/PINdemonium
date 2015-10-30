#include "InitFunctionCall.h"


#define IDAW_FULL_PATH "\"C:\\Program Files\\IDA 6.6\\idaw.exe\""
#define WORK_DIRECTORY "C:\\pin\\TempOEPin\\"						   //Base directory where temporary files and result will be created
#define FULLPATH(x)  WORK_DIRECTORY  x 								   //macro to create the full path of afile using the working the WORK_DIRECTORY define

#define TMP_DUMP_FILENAME "tmpDump.bin"								   //Name of the temporary (not IAT fixed) Dump
#define FINAL_DUMP_FILENAME "finalDump.bin"							   //Name of the final (IAT fixed) Dump
#define IDAIDB "finalDump.idb"										   //Name of the IDB
#define IDAPYTHON_LAUNCHER "idaPythonScript.bat"					   //Batch script to lauch IdaPython
#define IDAPYTHON_SCRIPT "showImports.py"							   //IdaPython script 
#define IDAPYTHON_RESULT_FILE "detectedInitFunc.txt"				   //File used by the IdaPython script to write back the results	


InitFunctionCall::InitFunctionCall(void)
{
	#ifdef _WIN64
		hScylla = W::LoadLibraryW(L"./ScyllaDLLx64.dll");
	#else
		hScylla = W::LoadLibraryW(L"./ScyllaDLLx86.dll");
	#endif
		INFO("Loading scylla\n ");
		if (hScylla)
		{
			ScyllaIatSearch = (def_ScyllaIatSearch)GetProcAddress(hScylla, "ScyllaIatSearch");
			ScyllaIatFixAutoA = (def_ScyllaIatFixAutoA)GetProcAddress(hScylla, "ScyllaIatFixAutoA");
			ScyllaDumpProcessA = (def_ScyllaDumpProcessA)GetProcAddress(hScylla, "ScyllaDumpProcessA");
		}


}


InitFunctionCall::~InitFunctionCall(void)
{
}




/**
Extract the .EXE file which has lauched the process having PID pid
**/
BOOL InitFunctionCall::GetFilePathFromPID(UINT32 dwProcessId, char **filename){
	
	for( IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) ){
		if(IMG_IsMainExecutable(img)){
			MYLOG("img name %s",(char *)IMG_Name(img).c_str());
			*filename = (char *)IMG_Name(img).c_str();
			return true;
		}
	}
	return false;
	
}

/**
	Get the Base Address(0x00400000) of the Process running with pid dwProcessId
**/
ADDRINT InitFunctionCall::GetExeModuleBase(UINT32 dwProcessId)
{
	W::MODULEENTRY32 lpModuleEntry = { 0 };
	W::HANDLE hSnapShot = W::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	lpModuleEntry.dwSize = sizeof(lpModuleEntry);
	Module32First(hSnapShot, &lpModuleEntry);

	CloseHandle(hSnapShot);

	return (ADDRINT)lpModuleEntry.modBaseAddr;
}

/**
	Get the size of the file passed as fp
**/
UINT32 InitFunctionCall::getFileSize(FILE * fp){
	fseek(fp, 0L, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
return size;
}

/**
Dump the current process memory and try to reconstruct the PE from the dump using "oep" as Original Entry Point 
**/
void InitFunctionCall::DumpProcess(ADDRINT oep, char *outputFile)
{
	INFO("----------------Dumping process----------------\n");

	ADDRINT iatStart = 0;
	UINT32 iatSize = 0;
	//XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX Change to  FULLPATH(TMP_DUMP_FILENAME) when finished test
	char *dumpFile = FULLPATH(FINAL_DUMP_FILENAME);  //Path of the file where the process will be dumped during the Dumping Process
	char *originalExe= (char *)malloc(MAX_PATH); // Path of the original PE which as launched the current process
	

	
	//Getting Current process PID and Base Address
	UINT32 pid = W::GetCurrentProcessId();
	MYLOG("Curr PID %d",pid);
	
	ADDRINT hMod = GetExeModuleBase(pid);
	if(!hMod){
		MYLOG("Can't find PID");
	}
	MYLOG("GetExeModuleBase %X\n", hMod);

	

	//----------- Dumping Process -------

	//Getting the path to the original exe which launched the process with PID "pid"
	BOOL success = GetFilePathFromPID(pid,&originalExe);
	if(!success){
		MYLOG("Error in getting original Path from Pid: %d\n",pid);
		return;
	}
	MYINFO("Original Exe Path: %s\n",originalExe);
		
	success = ScyllaDumpProcessA(pid,originalExe,hMod,oep,dumpFile);
	if(!success){
		MYINFO("Error Dumping  Pid: %d, FileToDump: %s, Hmod: %x, oep: %x, output: %s \n",pid,originalExe,hMod,oep,dumpFile);
		return;
	}
	MYINFO("Successfully dumped Pid: %d, FileToDump: %s, Hmod: %x, oep: %x, output: %s \n",pid,originalExe,hMod,oep,dumpFile);
		
	
	MYINFO("Tstdsadsadsada\n");
	/*
	//--------------- Searching the IAT --------------------
	int error = ScyllaIatSearch(pid, &iatStart, &iatSize, hMod + 0x00001028, TRUE);
	if(error){
		MYINFO("(IAT SEARCH) error %d \n",error);
		return;
	}
	MYINFO("adwedewdew\n");
	MYINFO("(IAT SEARCH) iatStart %x iatSize %x\n",iatStart, iatSize);
	

	//Fixing the IAT
	error = ScyllaIatFixAutoA(iatStart,iatSize,pid,dumpFile,outputFile);
	if(error){
		MYINFO("(IAT FIX) error %d",error);
		return;
	}
	MYINFO("[IAT FIX] Success");
	*/
}

UINT32 InitFunctionCall::run(ADDRINT curEip){

	MYINFO("--------------------------------------------------------");
	MYINFO("IP : %08", curEip);
	MYINFO("--------------------------------------------------------");

	char *outputFile = FULLPATH(FINAL_DUMP_FILENAME);
	DumpProcess(curEip,outputFile);
	
	//Running external idaPython script
	W::STARTUPINFO si ={0};
	W::PROCESS_INFORMATION pi ={0};

	si.cb=sizeof(si);
	// Create a file batch which run the IdaPython script and execute it
	char *cmd = IDAW_FULL_PATH" -A -S"FULLPATH(IDAPYTHON_SCRIPT)" "FULLPATH(FINAL_DUMP_FILENAME)" & rm " FULLPATH(IDAIDB); 
	FILE *idaLauncherFile = fopen(FULLPATH(IDAPYTHON_LAUNCHER),"w");
	fwrite(cmd,strlen(cmd),1,idaLauncherFile);
	fclose(idaLauncherFile);
	MYINFO("Launching the IdaPython Script %s Containing %s \n",FULLPATH(IDAPYTHON_LAUNCHER),cmd);
	
	if(!W::CreateProcess(FULLPATH(IDAPYTHON_LAUNCHER),NULL,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){
		MYINFO("(INITFUNCTIONCALL)Can't create the idaPython laucher");
		return 0;
	}
	W::WaitForSingleObject(pi.hProcess,INFINITE);
	W::CloseHandle(pi.hProcess);
	W::CloseHandle(pi.hThread);
	MYLOG("(INITFUNCTIONCALL)Everything good");


	//Read the result of IdaPython script
	FILE *fd = fopen(FULLPATH(IDAPYTHON_RESULT_FILE),"r");
	UINT32 file_size = getFileSize(fd);
	char * init_func_detected = (char *)malloc(file_size);
	fread(init_func_detected,file_size,1,fd);
	fclose(fd);

	MYLOG("Found init functions %s",init_func_detected);
	return 0;
}


