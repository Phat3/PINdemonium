#include "InitFunctionCall.h"

#define MAX_PID_LEN_DECIMAL_REP 6 
#define MAX_ADDRESS_SIZE 8

#define IDAW_FULL_PATH "\"C:\\Program Files\\IDA 6.6\\idaw.exe\""
#define WORK_DIRECTORY "C:\\pin\\TempOEPin\\"						   //Base directory where temporary files and result will be created
#define FULLPATH(x)  WORK_DIRECTORY  x 								   //macro to create the full path of afile using the working the WORK_DIRECTORY define

#define SCYLLA_FILENAME "Scylla\\ScyllaTest.exe"
#define TMP_DUMP_FILENAME "tmpDump.bin"								   //Name of the temporary (not IAT fixed) Dump
#define FINAL_DUMP_FILENAME "finalDump"							   //Name of the final (IAT fixed) Dump
#define IDAPYTHON_LAUNCHER "idaPythonScript.bat"					   //Batch script to lauch IdaPython
#define IDAPYTHON_SCRIPT "showImports.py"							   //IdaPython script 
#define IDAPYTHON_RESULT_FILE "detectedInitFunc.txt"				   //File used by the IdaPython script to write back the results	


InitFunctionCall::InitFunctionCall(void)
{


}


InitFunctionCall::~InitFunctionCall(void)
{
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

BOOL InitFunctionCall::existFile (char *name) {
    if (FILE *file = fopen(name, "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }   
}

UINT32 InitFunctionCall::run(ADDRINT curEip,WriteInterval wi){

	
	//Getting Current process PID and Base Address
	UINT32 pid = W::GetCurrentProcessId();
	MYINFO("Curr PID %d",pid);
	
	char current_dump[MAX_PATH+7];
	sprintf(current_dump,"%s_%d.bin",FULLPATH(FINAL_DUMP_FILENAME),ProcInfo::getInstance()->getDumpNumber());
	MYINFO("Current output file dump %s",current_dump);

	if(!launchScyllaDump(FULLPATH(SCYLLA_FILENAME),pid,curEip,current_dump)){
		MYERRORE("Scylla execution Failed");
		return 0;
	}

	char idb_to_rm[MAX_PATH+7];
	sprintf(idb_to_rm,"%s_%d.idb",FULLPATH(FINAL_DUMP_FILENAME),ProcInfo::getInstance()->getDumpNumber());
	
	launchIdaScript(IDAW_FULL_PATH, FULLPATH(IDAPYTHON_SCRIPT), current_dump,idb_to_rm );

	ProcInfo::getInstance()->incrementDumpNumber();

	//Read the result of IdaPython script
	
	FILE *fd = fopen(FULLPATH(IDAPYTHON_RESULT_FILE),"r");
	UINT32 file_size = getFileSize(fd);
	char * init_func_detected = (char *)malloc(file_size);
	fread(init_func_detected,file_size,1,fd);
	fclose(fd);

	MYINFO("Found init functions %s",init_func_detected);
	
	
	return 0;
}

BOOL InitFunctionCall::launchScyllaDump(char *scylla,int pid, int curEip,char *outputFile){	

	char scyllaCmd[MAX_PATH];    
	char scyllaArgs[ MAX_PID_LEN_DECIMAL_REP + MAX_ADDRESS_SIZE + MAX_PATH + 10];
	sprintf(scyllaCmd,"%s ",scylla);
	sprintf(scyllaArgs,"%s %d %x %s",scylla,pid,curEip,outputFile); //argv[0] is the name of the program
	MYINFO("Scylla cmd %s %s",scyllaCmd,scyllaArgs);
	//Running external idaPython script
	W::STARTUPINFO si ={0};
	W::PROCESS_INFORMATION pi ={0};

	si.cb=sizeof(si);

	if(!W::CreateProcess(scyllaCmd,scyllaArgs,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){
		MYINFO("(INITFUNCTIONCALL)Can't launch Scylla");
		return false;
	}
	W::WaitForSingleObject(pi.hProcess,INFINITE);
	W::CloseHandle(pi.hProcess);
	W::CloseHandle(pi.hThread);
	
	if(!existFile(outputFile)){
		MYINFO("(INITFUNCTIONCALL)Scylla Can't dump the process");
		return false;
	}
	MYINFO("(INITFUNCTIONCALL)Scylla Finished");
	return true;
}



BOOL InitFunctionCall::launchIdaScript(char *idaw,char *idaPythonScript,char * dumpFile,char * idaIdbToRm){
	char *idaScriptLauncher = FULLPATH(IDAPYTHON_LAUNCHER);
	
	//Running external idaPython script
	W::STARTUPINFO si ={0};
	W::PROCESS_INFORMATION pi ={0};

	si.cb=sizeof(si);
	// Create a file batch which run the IdaPython script and execute it
	char idaScript[MAX_PATH*4+20];
	sprintf(idaScript,"%s -A -S%s %s  ",idaw,idaPythonScript,dumpFile); 
	FILE *idaLauncherFile = fopen(idaScriptLauncher,"w");
	fwrite(idaScript,strlen(idaScript),1,idaLauncherFile);
	fclose(idaLauncherFile);
	MYINFO("Launching the IdaPython Script %s Containing %s \n",idaLauncherFile,idaScript);
	
	if(!W::CreateProcess(idaScriptLauncher,NULL,NULL,NULL,FALSE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi)){
		MYINFO("(INITFUNCTIONCALL)Can't launch idaPythonScript");
		return false;
	}
	W::WaitForSingleObject(pi.hProcess,INFINITE);
	W::CloseHandle(pi.hProcess);
	W::CloseHandle(pi.hThread);
	MYINFO("(INITFUNCTIONCALL)idaPythonScript FInished");
	return true;


}




