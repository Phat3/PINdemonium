#include "ProcInfo.h"


ProcInfo* ProcInfo::instance = 0;

ProcInfo* ProcInfo::getInstance()
{
	if (instance == 0)
		instance = new ProcInfo();
		
	return instance;
}


ProcInfo::ProcInfo()
{
	this->prev_ip = 0;
	this->popad_flag = FALSE;
	this->pushad_flag = FALSE;
	this->start_timer = -1;
	this->interresting_processes_name.insert("pin.exe");
	this->interresting_processes_name.insert("csrss.exe");
	this->retrieveInterestingPidFromNames();

}

ProcInfo::~ProcInfo(void)
{
}


/* ----------------------------- SETTER -----------------------------*/

void ProcInfo::setFirstINSaddress(ADDRINT address){
	this->first_instruction  = address;
}

void ProcInfo::setPrevIp(ADDRINT ip){
	this->prev_ip  = ip;
}

void ProcInfo::setPushadFlag(BOOL flag){
	this->pushad_flag = flag;
}


void ProcInfo::setPopadFlag(BOOL flag){
	this->popad_flag = flag;
}


void ProcInfo::setProcName(string name){
	this->full_proc_name = name;
	//get the starting position of the last element of the path (the exe name)
	int pos_exe_name = name.find_last_of("\\");
	string exe_name = name.substr(pos_exe_name + 1);
	//get the name from the last occurrence of / till the end of the string minus the file extension
	this->proc_name =  exe_name.substr(0, exe_name.length() - 4);
}

void ProcInfo::setInitialEntropy(float Entropy){
	this->InitialEntropy = Entropy;
}

void ProcInfo::setStartTimer(clock_t t){
	this->start_timer = t;
}




/* ----------------------------- GETTER -----------------------------*/


ADDRINT ProcInfo::getFirstINSaddress(){
	return this->first_instruction;
}

ADDRINT ProcInfo::getPrevIp(){
	return this->prev_ip;
}

std::vector<Section> ProcInfo::getSections(){
	return this->Sections;
}

BOOL ProcInfo::getPushadFlag(){
	return this->pushad_flag ;
}

BOOL ProcInfo::getPopadFlag(){
	return this->popad_flag;
}

string ProcInfo::getProcName(){
	return this->proc_name;
}

float ProcInfo::getInitialEntropy(){
	return this->InitialEntropy;
}

std::unordered_set<ADDRINT> ProcInfo::getJmpBlacklist(){
	return this->addr_jmp_blacklist;
}

clock_t ProcInfo::getStartTimer(){
	return this->start_timer;
}




/* ----------------------------- UTILS -----------------------------*/

void ProcInfo::PrintSections(){

	MYINFO("======= SECTIONS ======= \n");
	for(unsigned int i = 0; i < this->Sections.size(); i++) {
		Section item = this->Sections.at(i);
		MYINFO("%s	->	begin : %08x		end : %08x", item.name.c_str(), item.begin, item.end);
	}
	MYINFO("================================= \n");

}

//insert a new section in our structure
void ProcInfo::insertSection(Section section){
	this->Sections.push_back(section);
}

//return the section's name where the IP resides
string ProcInfo::getSectionNameByIp(ADDRINT ip){

	string s = "";
	for(unsigned int i = 0; i < this->Sections.size(); i++) {
		Section item = this->Sections.at(i);
		if(ip >= item.begin && ip <= item.end){
			s = item.name;
		}
	}
	return s;
}

void ProcInfo::insertHeapZone(HeapZone heap_zone){
	this->HeapMap.push_back(heap_zone);
}

void ProcInfo::removeLastHeapZone(){
	this->HeapMap.pop_back();
}

void ProcInfo::deleteHeapZone(UINT32 index){
     
	this->HeapMap.erase(this->HeapMap.begin()+index);
}

UINT32 ProcInfo::searchHeapMap(ADDRINT ip){

	int i=0;
	HeapZone hz;
	for(i=0; i<this->HeapMap.size();i++){
	    
		hz = this->HeapMap.at(i);
		if(ip >= hz.begin){
		   if(ip <= hz.end) 
			   return i;
		}
	}
	return -1;
}

HeapZone* ProcInfo::getHeapZoneByIndex(UINT32 index){

	return &this->HeapMap.at(index);
}


//return the entropy value of the entire program
float ProcInfo::GetEntropy(){

	IMG binary_image = APP_ImgHead();

	const double d1log2 = 1.4426950408889634073599246810023;
	double Entropy = 0.0;
	unsigned long Entries[256];
	unsigned char* Buffer;

	ADDRINT start_address = IMG_LowAddress(binary_image);
	ADDRINT end_address = IMG_HighAddress(binary_image);
	UINT32 size = end_address - start_address;

	Buffer = (unsigned char *)malloc(size);

	PIN_SafeCopy(Buffer , (void const *)start_address , size);

	memset(Entries, 0, sizeof(unsigned long) * 256);

	for (unsigned long i = 0; i < size; i++)
		Entries[Buffer[i]]++;
	for (unsigned long i = 0; i < 256; i++)
	{
		double Temp = (double) Entries[i] / (double) size;
		if (Temp > 0)
			Entropy += - Temp*(log(Temp)*d1log2); 
	}


	return Entropy;
}

void ProcInfo::insertInJmpBlacklist(ADDRINT ip){
	this->addr_jmp_blacklist.insert(ip);
}

BOOL ProcInfo::isInsideJmpBlacklist(ADDRINT ip){
	return this->addr_jmp_blacklist.find(ip) != this->addr_jmp_blacklist.end();
}

BOOL ProcInfo::isInterestingProcess(unsigned int pid){
	return this->interresting_processes_pid.find(pid) != this->interresting_processes_pid.end();
}


void ProcInfo::printHeapList(){
	for(unsigned index=0; index <  this->HeapMap.size(); index++) {
		MYINFO("Heapzone number  %u  start %08x end %08x",index,this->HeapMap.at(index).begin,this->HeapMap.at(index).end);
	}
}


BOOL ProcInfo::isInsideMainIMG(ADDRINT address){
	return mainImg.StartAddress <= address && address <= mainImg.EndAddress;

}

VOID ProcInfo::setMainIMGAddress(ADDRINT startAddr,ADDRINT endAddr){
	mainImg.StartAddress = startAddr;
	mainImg.EndAddress = endAddr;

}

//--------------------------------------------------Library--------------------------------------------------------------


//retrieve the PID of the processes marked as interesting
//for example : csrss.exe is interesting because we have to block Aall the openProcess to its PID
void ProcInfo::retrieveInterestingPidFromNames(){
  W::HANDLE hProcessSnap;
  W::HANDLE hProcess;
  W::PROCESSENTRY32 pe32;
  W::DWORD dwPriorityClass;

  // Take a snapshot of all processes in the system.
  hProcessSnap = W::CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

  // Set the size of the structure before using it.
  pe32.dwSize = sizeof( W::PROCESSENTRY32 );

  if( !Process32First( hProcessSnap, &pe32 ) )
  {
    printf("Process32First failed"); // show cause of failure
    CloseHandle( hProcessSnap );     // clean the snapshot object
	return;
  }
  // Now walk the snapshot of processes, and
  // display information about each process in turn
  do
  {
	  //if the name of the process is one of interest
	if( this->interresting_processes_name.find(pe32.szExeFile) != this->interresting_processes_name.end()){
		//add its pid to the set of the interesting PID
	  	this->interresting_processes_pid.insert(pe32.th32ProcessID);
	}
  } while( Process32Next( hProcessSnap, &pe32 ) );

  CloseHandle( hProcessSnap );
}


/**
add library in a list sorted by address
**/
VOID ProcInfo::addLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr){

	LibraryItem libItem;
	libItem.StartAddress = startAddr;
	libItem.EndAddress = endAddr;
	libItem.name = name;
	if (LibrarySet.empty()) {
		LibrarySet.push_back(libItem);
		MYINFO("Add  %s",libToString(libItem));
		return;
	}
	for(auto lib = LibrarySet.begin(); lib != LibrarySet.end(); ++lib) {
		if (lib->StartAddress < startAddr) {
			MYINFO("Add  %s",libToString(libItem));
			LibrarySet.insert(lib, libItem);
			return;
		}
	}
	LibrarySet.push_back(libItem);
	MYINFO("Add  %s",libToString(libItem));
	return ;

}

/**
Convert a LibraryItem object to string
**/
string ProcInfo::libToString(LibraryItem lib){
	std::stringstream ss;
	ss << "Library: " <<lib.name;
	ss << "\t\tstart: " << std::hex << lib.StartAddress;
	ss << "\tend: " << std::hex << lib.EndAddress;
	const std::string s = ss.str();	
	return s;
	
}

/**
Display on the log the currently filtered libs
**/
VOID  ProcInfo::showFilteredLibs(){
	for(std::vector<LibraryItem>::iterator lib = LibrarySet.begin(); lib != LibrarySet.end(); ++lib) {
		MYINFO("Filtered Lib %s",libToString(*lib));
	}
}

/**
Check the current name against a set of whitelisted library names
(IDEA don't track kernel32.dll ... but track custom dll which may contain malicious payloads)
**/
BOOL ProcInfo::isKnownLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr){
	BOOL isExaitDll = name.find("detect") != std::string::npos;
	if(isExaitDll){
		MYINFO("FOUND EXAIT DLL %s from %08x  to   %08x\n",name.c_str(),startAddr,endAddr);
		return FALSE;
	}
	return TRUE;
}

/*check if the address belong to a Library */
//TODO add a whiitelist of Windows libraries that will be loaded
BOOL ProcInfo::isLibraryInstruction(ADDRINT address){
	for(std::vector<LibraryItem>::iterator lib = LibrarySet.begin(); lib != LibrarySet.end(); ++lib) {
		if (lib->StartAddress <= address && address <= lib->EndAddress)
		//	MYINFO("Instruction at %x filtered", address);
			return TRUE;
	}
	
	return FALSE;	
}

//------------------------------------------------------------TEB------------------------------------------------------------


/**
Check if an address in on the Teb
**/
BOOL ProcInfo::isTebAddress(ADDRINT addr) {
	return (tebAddr <= addr && addr <= tebAddr + TEB_SIZE ) ;
}


VOID ProcInfo::initTebAddress(){

	W::_TEB *teb = W::NtCurrentTeb();
	//sprintf(tebStr,"%x",teb);
	tebAddr = (ADDRINT)teb;
	MYINFO("Init Teb base address %x",tebAddr);

}

//------------------------------------------------------------ Stack ------------------------------------------------------------

/**
Check if an address in on the stack
**/
BOOL ProcInfo::isStackAddress(ADDRINT addr) {
	return (stackBase - MAX_STACK_SIZE < addr && addr < stackBase );
}

/**
Initializing the base stack address by getting a value in the stack and searching the highest allocated address in the same memory region
**/
VOID ProcInfo::setStackBase(ADDRINT addr){
	//hasn't been already initialized
	if(stackBase == 0) {	
	
		W::MEMORY_BASIC_INFORMATION mbi;
		int numBytes = W::VirtualQuery((W::LPCVOID)addr, &mbi, sizeof(mbi));
		//get the stack base address by searching the highest address in the allocated memory containing the stack Address
		if((mbi.State == MEM_COMMIT || mbi.State == MEM_MAPPED) || mbi.State == MEM_IMAGE ){
			MYINFO("stack base addr:   -> %08x\n",  (int)mbi.BaseAddress+ mbi.RegionSize);
			stackBase = (int)mbi.BaseAddress+ mbi.RegionSize;
		}

		else{
			stackBase = addr;
		}
			MYINFO("Init FilterHandler Stack from %x to %x",stackBase,stackBase -MAX_STACK_SIZE);

	}	

}
//------------------------------------------------------------ Whitelist Addresses ------------------------------------------------------------

VOID ProcInfo::getWhiteListAddresses()
{
	
	//enumerateMyMemory();
	//PrintWhiteListedAddr();
	
	W::PROCESS_INFORMATION pi = {0};
	W::STARTUPINFO si   = {0};
	si.cb   = sizeof(si);


	MYINFO("running exe suspended\n");
	
	 // Create the process
	 int result = W::CreateProcess( full_proc_name.c_str(), NULL, NULL, NULL, TRUE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);
	 
	 if (!result){
		MYINFO("Error lauching the process\n");
		return;
	 }

	 bool completed = false; 
	 bool prova = false;

	 while ( !completed )
	  {
		W::DEBUG_EVENT DebugEvent;
		W::EXCEPTION_DEBUG_INFO& exception =  DebugEvent.u.Exception;
		if ( !W::WaitForDebugEvent(&DebugEvent, INFINITE) ){
		  printf("Errore debugger!\n");
		  return;
		}
		
		switch (DebugEvent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
		  //MYPRINT("\nCREATE PROCESS\n");
		  //enumerateMemory(pi.hProcess);
		  break;

		case EXIT_PROCESS_DEBUG_EVENT:
		   //MYPRINT("\nEXIT PROCESS\n");
		   //enumerateMemory(pi.hProcess);
		  completed = true;
		  break;
 
		case CREATE_THREAD_DEBUG_EVENT:
			//MYPRINT("\nCREATE THREAD\n");
		  //enumerateMemory(pi.hProcess);
		  break;

		case EXIT_THREAD_DEBUG_EVENT:
			 //MYPRINT("\nEXCEPTION\n");
		 // enumerateMemory(pi.hProcess);
		  break;
 
		case LOAD_DLL_DEBUG_EVENT:
			 //MYPRINT("\nLOAD DLL\n");
		  //enumerateMemory(pi.hProcess);
		  break;

		case UNLOAD_DLL_DEBUG_EVENT:
			 //MYPRINT("\nUNLOAD DLL\n");
		  //enumerateMemory(pi.hProcess);
		  break;
 
		case OUTPUT_DEBUG_STRING_EVENT:
			 //MYPRINT("\nSTRING EVENT\n");
		  //enumerateMemory(pi.hProcess);
		  break;

		case EXCEPTION_DEBUG_EVENT:
		   //MYPRINT("\nEXCEPTION\n");
		   exception = DebugEvent.u.Exception;
		   if( exception.ExceptionRecord.ExceptionCode == 0x80000003L)
		   {
			   if(!prova){
				prova = true;
			   }
			   else{
				  MYPRINT("\nEXCEPTION BREAK at %08x\n",  exception.ExceptionRecord.ExceptionAddress);
				  enumerateMemory(pi.hProcess);
				  W::TerminateProcess(pi.hProcess,0);
				  completed = true;
			   }
				 
		   }
		   break;

		default:
		  MYPRINT("\nIN DEFAULT\n");

		}
		if ( !W::ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, 0x00010002L) ){
		   printf("Errore debugger 2!\n");
		   return;
		}
	 }
	
	 printf("Mulanciato");
	 //W::Sleep(200000);
	 //enumerateMemory(pi.hProcess);
	 //PrintWhiteListedAddr();
	 		
}

VOID ProcInfo::enumerateMemory(W::HANDLE hProc){
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0;
	int match_string =0;
	MYINFO("\n\n----Memory----\n");
	do
	{
		numBytes = W::VirtualQueryEx(hProc,(W::LPCVOID)MyAddress, &mbi, sizeof(mbi));
		
		if((mbi.State == MEM_COMMIT || mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE) )
		{
			//ADDRINT end = (ADDRINT)mbi.BaseAddress + mbi.RegionSize;
			//MYPRINT("Whitelisted static %08x  ->  %08x\t STATE : %08x \t TYPE : %08x", (ADDRINT)mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Type);
			addWhitelistAddresses((ADDRINT)mbi.BaseAddress,mbi.RegionSize);

		}
		MyAddress += mbi.RegionSize;

	}
	while(numBytes);

	return;

}

VOID ProcInfo::enumerateMyMemory(){
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0;
	int match_string =0;
	do
	{
		numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi));
		
		if((mbi.State == MEM_COMMIT || mbi.State == MEM_MAPPED || mbi.State == MEM_IMAGE) )
		{
		
			addWhitelistAddresses((ADDRINT)mbi.BaseAddress,mbi.RegionSize);

		}
		MyAddress += mbi.RegionSize;

	}
	while(numBytes);

	return;

}



VOID ProcInfo::addWhitelistAddresses(ADDRINT baseAddr,ADDRINT regionSize){
	MemoryRange libItem;
	libItem.StartAddress = baseAddr;
	libItem.EndAddress = baseAddr + regionSize;
	whiteListMemory.push_back(libItem);

}

BOOL ProcInfo::isAddrInWhiteList(ADDRINT address){
	
	//Iterate through the already whitelisted memory addresses
	for(std::vector<MemoryRange>::iterator item = whiteListMemory.begin(); item != whiteListMemory.end(); ++item) {
		if(item->StartAddress <= address && address <= item->EndAddress){
			return TRUE;
		}						
	}
	if(isInsideMainIMG(address)){
		return TRUE;
	}
	//iterate through the allocated memory addresses
	for(std::vector<HeapZone>::iterator item = HeapMap.begin(); item != HeapMap.end(); ++item) {
		
		if(item->begin <= address && address <= item->end){
			return TRUE;
		}						
	}
	if (isLibraryInstruction(address)){
		return TRUE;
	}
	if(isTebAddress(address)){
		return TRUE;
	}

	return isStackAddress(address); //FilterHandler::getInstance()->isStackAddress(address);
}

void ProcInfo::PrintWhiteListedAddr(){
	//Iterate through the already whitelisted memory addresses

	//MYINFO("Whitelisted main image %08x  ->  %08x",mainImg.StartAddress,mainImg.EndAddress);
	MYINFO("BEFORE MERGE :");

	for(std::vector<MemoryRange>::iterator item = whiteListMemory.begin(); item != whiteListMemory.end(); ++item) {
		MYPRINT("Whitelisted static %08x  ->  %08x",item->StartAddress,item->EndAddress)		;				
	}

	//merge interval algorithm
	//IP1 : the set of intervals is sorted in ascending order
	//IP2 : the intervals never overlaps each other (at most the end of the previous is equals at the start of the current)
	
	//get the first element
	std::vector<MemoryRange>::iterator prev_item = whiteListMemory.begin();
	//start from the second till the end
	for(std::vector<MemoryRange>::iterator item = whiteListMemory.begin() + 1; item != whiteListMemory.end(); item++) {
		//if the end of the previous is equal to the start of the current we have tu merge the two interval and delete the previous
		if(item->StartAddress == prev_item->EndAddress){
			item->StartAddress = prev_item->StartAddress;
			//get the new iterator because we have erased an elemment and the old one is broken
			item = whiteListMemory.erase(prev_item);
		}
		prev_item = item;
	}

	MYPRINT("AFTER MERGE :");

	for(std::vector<MemoryRange>::iterator item = whiteListMemory.begin(); item != whiteListMemory.end(); ++item) {
		MYPRINT("Whitelisted static %08x  ->  %08x",item->StartAddress,item->EndAddress)		;				
	}

	/*
	//iterate through the allocated memory addresses
	for(std::vector<HeapZone>::iterator item = HeapMap.begin(); item != HeapMap.end(); ++item) {
		MYINFO("Whitelisted dynamic %08x  ->  %08x",item->begin,item->end)		;						
	}

	for(std::vector<LibraryItem>::iterator lib = LibrarySet.begin(); lib != LibrarySet.end(); ++lib) {
		MYINFO("Whitelisted library %08x  ->  %08x",lib->StartAddress,lib->StartAddress)		;	
	}

	MYINFO("Whitelisted Teb %08x  ->  %08x",tebAddr,  tebAddr + TEB_SIZE );

	MYINFO("Whitelisted Stack %08x  ->  %08x",stackBase - MAX_STACK_SIZE, stackBase);
	*/
	

}
