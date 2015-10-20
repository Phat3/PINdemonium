#include "InitFunctionCall.h"



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
	
	*/
	

	char *originalExe= (char *)malloc(MAX_PATH); // Path of the original PE which as launched the current process
	char *dumpFile = "./WItemdump2.bin";  //Path of the file where the process will be dumped during the Dumping Process

	UINT32 pid = W::GetCurrentProcessId();
	MYINFO("Curr PID %d",pid);
	//getting the Base Address
	
	ADDRINT hMod = GetExeModuleBase(pid);
	if(!hMod){
		MYINFO("Can't find PID");
	}
	MYINFO("GetExeModuleBase %X\n", hMod);

	

	//Dumping Process
	BOOL success = GetFilePathFromPID(pid,&originalExe);
	if(!success){
		MYINFO("Error in getting original Path from Pid: %d\n",pid);
		return 0;
	}
	MYINFO("Original Exe Path: %S\n",originalExe);
		
	success = ScyllaDumpProcessA(pid,originalExe,hMod,curEip,dumpFile);
	if(!success){
		MYINFO("Error Dumping  Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S \n",pid,originalExe,hMod,curEip,dumpFile);
		return 0;
	}
	MYINFO("Successfully dumped Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S \n",pid,originalExe,hMod,curEip,dumpFile);
	
	
	
	

	return 0;
}



