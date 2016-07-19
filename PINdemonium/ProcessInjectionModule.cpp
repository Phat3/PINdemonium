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
	std::vector<WriteInterval>& currentWriteSet =  WxorXHandler::getInstance()->getWxorXintervalInjected(pid);
	if(!currentWriteSet.empty()){
		MYINFO("Identify Injected execution %d",pid);
		HandleInjectedMemory(currentWriteSet,pid);
		wxorxHandler->clearWriteSet(pid); //clear the dumped writeItems from the current WriteSet
	}
}


VOID ProcessInjectionModule::HandleInjectedMemory(std::vector<WriteInterval>& currentWriteSet,W::DWORD pid){
	
	for(std::vector<WriteInterval>::iterator item = currentWriteSet.begin(); item != currentWriteSet.end(); ++item) {
		MYPRINT("\n\n-------------------------------------------------------------------------------------------------------");
		MYPRINT("------------------------------------ INJECTED STUB inside pid %d begin: %08x TO %08x -------------------------------------",pid,item->getAddrBegin(),item->getAddrEnd());
		MYPRINT("-------------------------------------------------------------------------------------------------------\n");
		MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
		MYPRINT("- - - - - - - - - - - - - - - - - - - - - STAGE 1: DUMPING - - - - - - - - - - - - - - - - - - - - - - - - -");
		MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
		string cur_dump_path = DumpRemoteWriteInterval(&(*item), pid);	
		report->createReportDump(item->getAddrBegin(),item->getAddrBegin(),item->getAddrEnd(),Config::getInstance()->getDumpNumber(),false,pid);
		
		//check if the memory has been dumped correctly and execute the heuristics
		if (cur_dump_path != ""){
			ExecuteHeuristics(cur_dump_path);
		}
		
		report->closeReportDump();
		config->incrementDumpNumber();

	}
}


/**
Dump on disk the memory range written on the remote process address space with  
return a string containing the path of the dumped memory
**/
string ProcessInjectionModule::DumpRemoteWriteInterval(WriteInterval* item,W::DWORD pid){
	//Dump remote process memory for each item inside the  currentWriteSet
	W::SIZE_T dwBytesRead = 0;
	UINT32 size =  item->getAddrEnd()-item->getAddrBegin();
	unsigned char * buffer = (unsigned char *)malloc(size);
	W::HANDLE process = W::OpenProcess(PROCESS_VM_READ,false,pid);
	if(W::ReadProcessMemory(process,(W::LPVOID)item->getAddrBegin(),buffer,  size,&dwBytesRead)){
		string path = config->getInjectionDir()+"/injection_" + std::to_string((long double)pid)+"_"+std::to_string((long double)config->getDumpNumber())+".bin";
		Helper::writeBufferToFile(buffer,size,path);
		MYINFO("Dumped remote injected memory inside pid %d to %s",pid,path.c_str());
		return path;
	}
	else{
		MYERRORE("Error reading injected process %d  memory %s",pid,W::GetLastError());
		return "";
	}	

}



/*
	Executes the heuristics on the dumped memory
*/
VOID ProcessInjectionModule::ExecuteHeuristics(string path_to_analyse){
		MYPRINT("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
		MYPRINT("- - - - - - - - - - - - - - - - - - - - - STAGE 2: ANALYZING DUMP - - - - - - - - - - - - - - - - - - - - - -");
		MYPRINT("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
		vector<string> dumps_to_analyse;
		dumps_to_analyse.push_back(path_to_analyse);
		Heuristics::yaraHeuristic(dumps_to_analyse);
	
}