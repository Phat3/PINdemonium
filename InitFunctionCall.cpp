#include "InitFunctionCall.h"


#define WORK_DIRECTORY "C:\\Users\\phate\\Desktop\\pin\\TempOEPin\\"   //Base directory where temporary files and result will be created
#define TMP_DUMP_FILENAME "tmpDump.tmp"								   //Name of the temporary (not IAT fixed) Dump
#define FINAL_DUMP_FILENAME "finalDump.bin"							   //Name of the final (IAT fixed) Dump
#define IDAPYTHON_LAUNCHER "idaInitFuncDetect.bat"					   //Batch script to lauch IdaPython
#define IDAPYTHON_RESULT_FILE "detectedInitFunc.txt"


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


ADDRINT InitFunctionCall::GetExeModuleBase(UINT32 dwProcessId)
{
	W::MODULEENTRY32 lpModuleEntry = { 0 };
	W::HANDLE hSnapShot = W::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	lpModuleEntry.dwSize = sizeof(lpModuleEntry);
	Module32First(hSnapShot, &lpModuleEntry);

	CloseHandle(hSnapShot);

	return (ADDRINT)lpModuleEntry.modBaseAddr;
}

UINT32 InitFunctionCall::getFileSize(FILE * fp){
	fseek(fp, 0L, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
return size;
}


void InitFunctionCall::DumpProcess(ADDRINT oep, char *outputFile)
{
	INFO("----------------Dumping process----------------\n");

	ADDRINT iatStart = 0;
	UINT32 iatSize = 0;
	char *dumpFile = WORK_DIRECTORY  FINAL_DUMP_FILENAME;  //Path of the file where the process will be dumped during the Dumping Process
	char *originalExe= (char *)malloc(MAX_PATH); // Path of the original PE which as launched the current process
	

	

	UINT32 pid = W::GetCurrentProcessId();
	MYLOG("Curr PID %d",pid);
	//getting the Base Address
	
	ADDRINT hMod = GetExeModuleBase(pid);
	if(!hMod){
		MYLOG("Can't find PID");
	}
	MYLOG("GetExeModuleBase %X\n", hMod);

	


	//Dumping Process
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
	//Searching the IAT
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

UINT32 InitFunctionCall::run(ADDRINT curEip,WriteInterval wi){
	/*
	MYLOG("Testing if an Init function is called inside the WriteInterval");
	int w_int_size = wi.getAddrEnd() - wi.getAddrBegin();
	unsigned int bytes = 0;
	MYLOG("WriteINt size: %d",w_int_size );

	unsigned char *inst_buffer = (unsigned char *)malloc(w_int_size);	
	
	PIN_SafeCopy(inst_buffer,(void *)(wi.getAddrBegin()),w_int_size);
	
	MYLOG("first bytes at inst_buffer: %x  first bytes at writeItem: %x",*inst_buffer,*((char *)wi.getAddrBegin()));
	FILE *fd = fopen("./WItemdump.bin","w");
	fwrite(inst_buffer,w_int_size,1,fd);
	fclose(fd);
	MYLOG("Dump Created");
	

	char *originalExe= (char *)malloc(MAX_PATH); // Path of the original PE which as launched the current process
	char *dumpFile = DUMP_FILENAME;  //Path of the file where the process will be dumped during the Dumping Process

	UINT32 pid = W::GetCurrentProcessId();
	MYLOG("Curr PID %d",pid);
	//getting the Base Address
	
	ADDRINT hMod = GetExeModuleBase(pid);
	if(!hMod){
		MYLOG("Can't find PID");
	}
	MYLOG("GetExeModuleBase %X\n", hMod);

	

	//Dumping Process
	BOOL success = GetFilePathFromPID(pid,&originalExe);
	if(!success){
		MYLOG("Error in getting original Path from Pid: %d\n",pid);
		return 0;
	}
	MYLOG("Original Exe Path: %S\n",originalExe);
		
	success = ScyllaDumpProcessA(pid,originalExe,hMod,curEip,dumpFile);
	if(!success){
		MYLOG("Error Dumping  Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S \n",pid,originalExe,hMod,curEip,dumpFile);
		return 0;
	}
	MYLOG("Successfully dumped Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S \n",pid,originalExe,hMod,curEip,dumpFile);
	
	
	*/
	
	char *outputFile = WORK_DIRECTORY FINAL_DUMP_FILENAME;
	DumpProcess(curEip,outputFile);
	//Running external idaPython script
	W::STARTUPINFO si ={0};
	W::PROCESS_INFORMATION pi ={0};



	si.cb=sizeof(si);

	if(!W::CreateProcess(WORK_DIRECTORY IDAPYTHON_LAUNCHER,NULL,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){
		MYLOG("(INITFUNCTIONCALL)Can't create the idaPython laucher");
		return 0;
	}
	W::WaitForSingleObject(pi.hProcess,INFINITE);
	W::CloseHandle(pi.hProcess);
	W::CloseHandle(pi.hThread);
	MYLOG("(INITFUNCTIONCALL)Everything good");


	//Read the result of IdaPython script
	FILE *fd = fopen(WORK_DIRECTORY IDAPYTHON_RESULT_FILE,"r");
	UINT32 file_size = getFileSize(fd);
	char * init_func_detected = (char *)malloc(file_size);
	fread(init_func_detected,file_size,1,fd);
	fclose(fd);

	MYLOG("Found init functions %s",init_func_detected);
	return 0;
}


