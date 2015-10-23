#include "GdbDebugger.h"

#define BUFSIZE 10000

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
   

// Get a handle to an input file for the parent. 
// This example assumes a plain text file and uses string output to verify data flow. ReadFromPipe();
// Write to the pipe that is the standard input for a child process. 
// Data is written to the pipe's buffers, so it is not necessary to wait
// until the child process is running before writing data.
 /*
   printf( "\n->WAIT\n", argv[1]);
   Sleep(3000);
   printf( "\n->WAIT DONE\n", argv[1]);
   ReadFromPipe();
   

   WriteToPipe(); 
   printf( "\n->Contents of %s written to child STDIN pipe.\n", argv[1]);
   ReadFromPipe();	

   printf( "\n->WAIT\n", argv[1]);
   Sleep(3000);
   printf( "\n->WAIT DONE\n", argv[1]);

   WriteToPipe(); 
   printf( "\n->Contents of %s written to child STDIN pipe.\n", argv[1]);
   ReadFromPipe(); 

   printf( "\n->WAIT\n", argv[1]);
   Sleep(3000);
   printf( "\n->WAIT DONE\n", argv[1]);

   WriteToPipe(); 
   printf( "\n->Contents of %s written to child STDIN pipe.\n", argv[1]);
   ReadFromPipe(); 

  
    Sleep(3000);

   printf("\n->End of parent execution.\n");
   */

}


GdbDebugger::~GdbDebugger(void)
{
}



// ----------------------------- UTILS ----------------------------- //


void GdbDebugger::CreateChildProcess()
// Create a child process that uses the previously created pipes for STDIN and STDOUT.
{ 
   TCHAR szCmdline[]=TEXT("C:\\MinGW\\bin\\gdb.exe");
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


void GdbDebugger::WriteToPipe(void) 

// Read from a file and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data. 
{ 
   DWORD dwRead=5, dwWritten; 
   CHAR chBuf[BUFSIZE] = "info\n";
   BOOL bSuccess = FALSE;
       
   bSuccess = WriteFile(g_hChildStd_IN_Wr, chBuf, dwRead, &dwWritten, NULL);

} 
 
void GdbDebugger::ReadFromPipe(void) 

// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT. 
// Stop when there is no more data. 
{ 
   DWORD dwRead, dwWritten; 
   CHAR chBuf[BUFSIZE]; 
   BOOL bSuccess = FALSE;
   HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

   ReadFile( g_hChildStd_OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
 
} 

void GdbDebugger::ErrorExit(char * error) 
{
    ExitProcess(1);
}

void GdbDebugger::executeCmd(char * cmd){
	this->WriteToPipe();
	this->ReadFromPipe();
} 
