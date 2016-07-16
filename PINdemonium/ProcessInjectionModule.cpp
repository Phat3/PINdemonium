#include "ProcessInjectionModule.h"


ProcessInjectionModule* ProcessInjectionModule::instance = 0;

ProcessInjectionModule* ProcessInjectionModule::getInstance()
{
	if (instance == 0)
		instance = new ProcessInjectionModule();
	return instance;
}

ProcessInjectionModule::ProcessInjectionModule(void)
{
	wxorxHandler = WxorXHandler::getInstance();
	config = Config::getInstance();
	report = Report::getInstance();


}


VOID ProcessInjectionModule::AddInjectedWrite(ADDRINT start, UINT32 size, W::DWORD pid ){
	wxorxHandler->writeSetManager(start,size,pid);
}

VOID ProcessInjectionModule::CheckInjectedExecution(W::DWORD pid ){
	std::vector<WriteInterval>* currentWriteSet =  WxorXHandler::getInstance()->getWxorXintervalInjected(pid);
	if(currentWriteSet){
		printf("identified injection and execution");
		HandleInjectedMemory(currentWriteSet,pid);
		wxorxHandler->clearWriteSet(pid); //clear the dumped writeItems from the current WriteSet
	}
}


VOID ProcessInjectionModule::HandleInjectedMemory(std::vector<WriteInterval>* currentWriteSet,W::DWORD pid){
	MYINFO("Dumping memory from %d",pid);
	W::HANDLE process = W::OpenProcess(PROCESS_VM_READ,false,pid);
	
	for(std::vector<WriteInterval>::iterator item = currentWriteSet->begin(); item != currentWriteSet->end(); ++item) {
		string cur_dump_path = DumpRemoteWriteInterval(&(*item), process);
		report->createReportDump(item->getAddrBegin(),item->getAddrBegin(),item->getAddrEnd(),Config::getInstance()->getDumpNumber(),false,pid);
		report->closeReportDump();
		config->incrementDumpNumber();

	}
}


// dump on disk the write interval  on the remote process with pid=pid and return a stringcontaining the path of the dumped memory
string ProcessInjectionModule::DumpRemoteWriteInterval(WriteInterval* item,W::HANDLE process){
	//Dump remote process memory for each item inside the  currentWriteSet
	W::SIZE_T dwBytesRead = 0;
	UINT32 size =  item->getAddrEnd()-item->getAddrBegin();
	unsigned char * buffer = (unsigned char *)malloc(size);
	UINT32 pid = W::GetProcessId(process);
	if(W::ReadProcessMemory(process,(W::LPVOID)item->getAddrBegin(),buffer,  size,&dwBytesRead)){
		string path = config->getInjectionDir()+"/injection_" + std::to_string((long double)pid)+"_"+std::to_string((long double)config->getDumpNumber())+".bin";
		WriteBufferToFile(buffer,size,path);
		MYINFO("Remote injection inside pid %d dumped at %s",pid,path.c_str());
		return path;
	}
	else{
		MYERRORE("Error reading injected process memory %s",W::GetLastError());
		return "";
	}	

}


VOID ProcessInjectionModule::WriteBufferToFile(unsigned char *buffer,UINT32 dwBytesToWrite,string path){

    W::DWORD dwBytesWritten = 0;

	  W::HANDLE hFile = W::CreateFile(path.c_str(),                // name of the write
                       GENERIC_WRITE,          // open for writing
                       0,                      // do not share
                       NULL,                   // default security
                       CREATE_NEW,             // create new file only
                       FILE_ATTRIBUTE_NORMAL,  // normal file
                       NULL);                  // no attr. template

   

     W::WriteFile( 
                    hFile,           // open file handle
                    buffer,      // start of data to write
                    dwBytesToWrite,  // number of bytes to write
                    &dwBytesWritten, // number of bytes that were written
                    NULL);            // no overlapped structure

}