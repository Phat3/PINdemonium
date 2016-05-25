#include "GdbDebugger.h"

#define BUFSIZE 10000

#define GDB_PATH "C:\\MinGW\\bin\\gdb.exe"

GdbDebugger* GdbDebugger::instance = 0;

//singleton
GdbDebugger* GdbDebugger::getInstance()
{
	if (instance == 0)
		instance = new GdbDebugger();
	return instance;
}

GdbDebugger::GdbDebugger(void)
{
   SECURITY_ATTRIBUTES saAttr; 
   //Set the bInheritHandle flag so pipe handles are inherited. 
   saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
   saAttr.bInheritHandle = TRUE; 
   saAttr.lpSecurityDescriptor = NULL; 
   //Create a pipe for the child process's STDIN. 
   if (! CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) 
      ErrorExit(TEXT("Stdin CreatePipe")); 	
   // Ensure the write handle to the pipe for STDIN is not inherited. 
   if ( ! SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0) )
      ErrorExit(TEXT("Stdin SetHandleInformation")); 
   // Create the child process.   
   CreateChildProcess();
   ReadFromPipe();
}


GdbDebugger::~GdbDebugger(void)
{
}

// ----------------------------- SETTER ----------------------------- //

void GdbDebugger::connectRemote(int port){
	std::stringstream cmd;
	cmd << "target remote :" << port;
	this->executeCmd((char *)cmd.str().c_str());
}


// ----------------------------- UTILS ----------------------------- //


void GdbDebugger::CreateChildProcess()
// Create a child process that uses the previously created pipes for STDIN and STDOUT.
{ 
	TCHAR szCmdline[]=TEXT(GDB_PATH);
	PROCESS_INFORMATION piProcInfo ={0}; 
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE; 
	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN and STDOUT handles for redirection.
	ZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
	siStartInfo.cb = sizeof(STARTUPINFO); 
	siStartInfo.hStdError =  GetStdHandle(STD_ERROR_HANDLE);
	siStartInfo.hStdOutput =  GetStdHandle(STD_OUTPUT_HANDLE);
	siStartInfo.hStdInput = g_hChildStd_IN_Rd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES; 
	// Create the child process.    
	bSuccess = CreateProcess(NULL, 
		szCmdline,     // command line 
		NULL,          // process security attributes 
		NULL,          // primary thread security attributes 
		TRUE,          // handles are inherited 
		CREATE_NEW_CONSOLE,             // creation flags 
		NULL,          // use parent's environment 
		NULL,          // use parent's current directory 
		&siStartInfo,  // STARTUPINFO pointer 
		&piProcInfo);  // receives PROCESS_INFORMATION 
   
	// If an error occurs, exit the application. 
	if ( ! bSuccess ) 
		ErrorExit(TEXT("CreateProcess"));
	else 
	{
		// Close handles to the child process and its primary thread.
		// Some applications might keep these handles to monitor the status
		// of the child process, for example. 
		CloseHandle(piProcInfo.hProcess);
		CloseHandle(piProcInfo.hThread);
	}
}

// Read from a file and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data. 
void GdbDebugger::WriteToPipe(char* cmd) { 
   DWORD dwRead = strlen(cmd), dwWritten; 
   BOOL bSuccess = FALSE;       
   bSuccess = WriteFile(g_hChildStd_IN_Wr, cmd, dwRead, &dwWritten, NULL);
} 


// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT. 
// Stop when there is no more data. 
void GdbDebugger::ReadFromPipe(void){ 
   DWORD dwRead, dwWritten; 
   CHAR chBuf[BUFSIZE]; 
   BOOL bSuccess = FALSE;
   HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
   ReadFile( g_hChildStd_OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL); 
} 


void GdbDebugger::ErrorExit(char * error) {
    ExitProcess(1);
}

void GdbDebugger::executeCmd(char* cmd){
	this->WriteToPipe(cmd);
	this->ReadFromPipe();
} 
