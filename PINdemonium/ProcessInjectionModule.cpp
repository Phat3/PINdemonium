#include "ProcessInjectionModule.h"

int ProcessInjectionModule::number = 0;
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


}


VOID ProcessInjectionModule::AddInjectedWrite(ADDRINT start, UINT32 size, W::DWORD pid ){
	wxorxHandler->writeSetManager(start,size,pid);
}

VOID ProcessInjectionModule::CheckInjectedExecution(W::DWORD pid ){
	std::vector<WriteInterval>* currentWriteSet =  WxorXHandler::getInstance()->getWxorXintervalInjected(pid);
	if(currentWriteSet){
		printf("identified injection and execution");
		DumpInjectedMemory(currentWriteSet,pid);
	}
}

VOID ProcessInjectionModule::DumpInjectedMemory(std::vector<WriteInterval>* currentWriteSet,W::DWORD pid){
	printf("dumping memory from %d",pid);
	W::HANDLE process = W::OpenProcess(PROCESS_VM_READ,false,pid);
	W::SIZE_T dwBytesRead = 0;
	for(std::vector<WriteInterval>::iterator item = currentWriteSet->begin(); item != currentWriteSet->end(); ++item) {
		UINT32 size =  item->getAddrEnd()-item->getAddrBegin();
		unsigned char * buffer = (unsigned char *)malloc(size);
		// copy the heap zone into the buffer 
		if(W::ReadProcessMemory(process,(W::LPVOID)item->getAddrBegin(),buffer,  size,&dwBytesRead)){
			string path = "C:\\pin\\injection_test_" + std::to_string((long double)number);
			printf("creating %s",path.c_str());
			MYINFO("Remote injection dumped");
			number++;
			WriteBufferToFile(buffer,size,path);
		}
		else{
			MYERRORE("Error reading injected process memory %s",W::GetLastError());
		}

		
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