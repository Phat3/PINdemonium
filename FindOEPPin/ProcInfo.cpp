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

std::vector<Section> ProcInfo::getProtectedSections(){
	return this->protected_section;
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

std::vector<HeapZone> ProcInfo::getHeapMap(){
	return this->HeapMap;
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

//--------------------------------------------------Library--------------------------------------------------------------


BOOL ProcInfo::isLibItemDuplicate(UINT32 address , std::vector<LibraryItem> Libraries ){

	for(std::vector<LibraryItem>::iterator lib =  Libraries.begin(); lib != Libraries.end(); ++lib) {
		if ( address == lib->StartAddress ){
		return TRUE;
		}
	}
	return FALSE;
}

/**
add library in a list sorted by address
**/
VOID ProcInfo::addLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr){


	LibraryItem libItem;
	libItem.StartAddress = startAddr;
	libItem.EndAddress = endAddr;
	libItem.name = name;

	if(isKnownLibrary(name,startAddr,endAddr)){
		
		//check if the library is present yet in the list of knownLibraries
	    if(!isLibItemDuplicate(startAddr , knownLibraries)){

		knownLibraries.push_back(libItem);
		//MYINFO("Add to known Library %s",libToString(libItem).c_str());

		}

		return;
	
	}
	else{

		//check if the library is present yet in the list of unknownLibraries
		if(!isLibItemDuplicate(startAddr , unknownLibraries)){

		unknownLibraries.push_back(libItem);
		//MYINFO("Add to unknown Library %s",libToString(libItem).c_str());

		}
		return;
	}

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
Check the current name against a set of whitelisted library names
(IDEA don't track kernel32.dll ... but track custom dll which may contain malicious payloads)
**/
BOOL ProcInfo::isKnownLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr){
	
	BOOL isExaitDll = name.find("detect") != std::string::npos;
	if(isExaitDll){
		//MYINFO("FOUND EXAIT DLL %s from %08x  to   %08x\n",name.c_str(),startAddr,endAddr);
		return FALSE;
	}
	else
		return TRUE;
	/*
	//POC - filter out the GDI32.dll
	if(name.find("GDI") != std::string::npos){
		return TRUE;
	}
	else{
		return FALSE;
	}
	*/

}

/*check if the address belong to a Library */
//TODO add a whiitelist of Windows libraries that will be loaded
BOOL ProcInfo::isLibraryInstruction(ADDRINT address){
	 
	//check inside known libraries
	for(std::vector<LibraryItem>::iterator lib = knownLibraries.begin(); lib != knownLibraries.end(); ++lib) {
		if (lib->StartAddress <= address && address <= lib->EndAddress){
		//	MYINFO("Instruction at %x filtered", address);
		//MYINFO("KNOWN LIBRARIES\n");
		return TRUE;}
	}
	//check inside unknown libraries
	for(std::vector<LibraryItem>::iterator lib = unknownLibraries.begin(); lib != unknownLibraries.end(); ++lib) {
		if (lib->StartAddress <= address && address <= lib->EndAddress){
		//	MYINFO("Instruction at %x filtered", address);
		//MYINFO("UNKKNOWN LIBRARIES\n");
			return TRUE;   
		}
	}
	
	//MYINFO("FALSE\n");
	return FALSE;	
}

BOOL ProcInfo::isKnownLibraryInstruction(ADDRINT address){
	//check inside known libraries
	for(std::vector<LibraryItem>::iterator lib = knownLibraries.begin(); lib != knownLibraries.end(); ++lib) {
		if (lib->StartAddress <= address && address <= lib->EndAddress)
		//	MYINFO("Instruction at %x filtered", address);
			return TRUE;
	}
	
	return FALSE;	
}


void ProcInfo::addProcAddresses(){
	setCurrentMappedFiles();
	addPebAddress();
	addContextDataAddress();
	addCodePageDataAddress();
	addSharedMemoryAddress();
	addProcessHeapsAndCheckAddress(NULL);
	addpShimDataAddress();
	addpApiSetMapAddress();
	addKUserSharedDataAddress();

}



//------------------------------------------------------------PEB------------------------------------------------------------
VOID ProcInfo::addPebAddress(){

	typedef int (WINAPI* ZwQueryInformationProcess)(W::HANDLE,W::DWORD,W::PROCESS_BASIC_INFORMATION*,W::DWORD,W::DWORD*);
	ZwQueryInformationProcess MyZwQueryInformationProcess;
 
	W::PROCESS_BASIC_INFORMATION tmppeb;
	W::DWORD tmp;
 
	W::HMODULE hMod = W::GetModuleHandle("ntdll.dll");
	MyZwQueryInformationProcess = (ZwQueryInformationProcess)W::GetProcAddress(hMod,"ZwQueryInformationProcess");
 
	MyZwQueryInformationProcess(W::GetCurrentProcess(),0,&tmppeb,sizeof(W::PROCESS_BASIC_INFORMATION),&tmp);
	peb = (PEB *) tmppeb.PebBaseAddress;
	
	//MYINFO("Init Peb base address %08x  -> %08x",(ADDRINT)peb, (ADDRINT)peb + sizeof(PEB));

}

BOOL ProcInfo::isPebAddress(ADDRINT addr) {

	return ((ADDRINT)peb <= addr && addr <= (ADDRINT)peb + sizeof(PEB) ) ;
} 


//------------------------------------------------------------TEB------------------------------------------------------------



//Check if an address in on the Teb
BOOL ProcInfo::isTebAddress(ADDRINT addr) {
	for(std::vector<MemoryRange>::iterator it = tebs.begin(); it != tebs.end(); ++it){
		if(it->StartAddress <= addr && addr <= it->EndAddress){
			return TRUE;
		}
	}
	return FALSE;
}


VOID ProcInfo::addThreadTebAddress(){

	W::_TEB *tebAddr = W::NtCurrentTeb();
	//sprintf(tebStr,"%x",teb);
	MemoryRange cur_teb;
	cur_teb.StartAddress = (ADDRINT)tebAddr;
	cur_teb.EndAddress = (ADDRINT)tebAddr +TEB_SIZE;
	//MYINFO("Init Teb base address %x   ->  %x",cur_teb.StartAddress,cur_teb.EndAddress);
	tebs.push_back(cur_teb);

}

//------------------------------------------------------------ Stack ------------------------------------------------------------

/**
Check if an address in on the stack
**/
BOOL ProcInfo::isStackAddress(ADDRINT addr) {
	for(std::vector<MemoryRange>::iterator it = stacks.begin(); it != stacks.end(); ++it){
		if(it->StartAddress <= addr && addr <= it->EndAddress){
			return TRUE;
		}
	}
	return FALSE;
}

/**
Initializing the base stack address by getting a value in the stack and searching the highest allocated address in the same memory region
**/
VOID ProcInfo::addThreadStackAddress(ADDRINT addr){
	//hasn't been already initialized
	MemoryRange stack;
	W::MEMORY_BASIC_INFORMATION mbi;
	int numBytes = W::VirtualQuery((W::LPCVOID)addr, &mbi, sizeof(mbi));
	//get the stack base address by searching the highest address in the allocated memory containing the stack Address
	if(mbi.State == MEM_COMMIT || mbi.Type == MEM_PRIVATE ){
		//MYINFO("stack base addr:   -> %08x\n",  (int)mbi.BaseAddress+ mbi.RegionSize);
		stack.EndAddress = (int)mbi.BaseAddress+ mbi.RegionSize;
	}

	else{
		stack.EndAddress = addr;
	}
	//check integer underflow ADDRINT
	if(stack.EndAddress <= MAX_STACK_SIZE ){
		stack.StartAddress =0;
	}
	else{
		stack.StartAddress = stack.EndAddress - MAX_STACK_SIZE;
	}
	MYINFO("Init Stacks by adding from %x to %x",stack.StartAddress,stack.EndAddress);
	stacks.push_back(stack);
	



}
//------------------------------------------------------------ Memory Mapped Files------------------------------------------------------------
//Add to the mapped files list the region marked as mapped when the application starts
VOID ProcInfo::setCurrentMappedFiles(){
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0;
	
	//delete old elements
	mappedFiles.clear();

	//Code to display the name of the mapped file has been commented out
//	typedef W::DWORD (WINAPI *LPFN_GetMappedFileNameW)(W::HANDLE hProcess, W::LPVOID lpv, W::LPWSTR lpFilename, W::DWORD nSize);
//	W::HINSTANCE hPsapi = NULL;
//	LPFN_GetMappedFileNameW lpGetMappedFileNameW = NULL;
//	hPsapi = W::LoadLibraryW(L"psapi.dll");
//	lpGetMappedFileNameW = (LPFN_GetMappedFileNameW) W::GetProcAddress(hPsapi, "GetMappedFileNameW");
	
	do{
		numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi));
		if(mbi.Type == MEM_MAPPED){
			//wchar_t name[MAX_PATH];
			//lpGetMappedFileNameW(W::GetCurrentProcess(), mbi.BaseAddress,name,MAX_PATH);
			
			MemoryRange range;
			range.StartAddress = (ADDRINT)mbi.BaseAddress;
			range.EndAddress = (ADDRINT)mbi.BaseAddress+mbi.RegionSize;
			mappedFiles.push_back(range);
		//	MYINFO("Init Mapped File base address %08x -> %08x",range.StartAddress ,range.EndAddress);
		}
		MyAddress += mbi.RegionSize;
	}
	while(numBytes);
}

BOOL ProcInfo::isMappedFileAddress(ADDRINT addr){
	for(std::vector<MemoryRange>::iterator item = mappedFiles.begin(); item != mappedFiles.end(); ++item) {
		if(item->StartAddress <= addr && addr <= item->EndAddress){
			return true;
		}			
	}
	return false;
}

VOID  ProcInfo::printMappedFileAddress(){
	for(std::vector<MemoryRange>::iterator item = mappedFiles.begin(); item != mappedFiles.end(); ++item) {
		MYINFO("Mapped file %08x -> %08x ",item->StartAddress , item->EndAddress);
	}
}

//Add dynamically created mapped files to the mapped files list
VOID ProcInfo::addMappedFilesAddress(ADDRINT startAddr){
	MemoryRange mappedFile;
	if(getMemoryRange((ADDRINT)startAddr,mappedFile)){
		MYINFO("Adding mappedFile base address  %08x -> %08x ",mappedFile.StartAddress,mappedFile.EndAddress);
		mappedFiles.push_back(mappedFile);
	}
}


//------------------------------------------------------------ Other Memory Location ------------------------------------------------------------
BOOL ProcInfo::isGenericMemoryAddress(ADDRINT address){
	for(std::vector<MemoryRange>::iterator item = genericMemoryRanges.begin(); item != genericMemoryRanges.end(); ++item) {
		if(item->StartAddress <= address && address <= item->EndAddress){
			return true;
		}			
	}
	return false;
}
/**
Fill the MemoryRange passed as parameter with the startAddress and EndAddress of the memory location in which the address is contained
ADDRINT address:  address of which we want to retrieve the memory region
MemoryRange& range: MemoryRange which will be filled 
return TRUE if the address belongs to a memory mapped area otherwise return FALSE
**/
BOOL ProcInfo::getMemoryRange(ADDRINT address, MemoryRange& range){
		
		W::MEMORY_BASIC_INFORMATION mbi;
		int numBytes = W::VirtualQuery((W::LPCVOID)address, &mbi, sizeof(mbi));
		if(numBytes == 0){
			MYERRORE("VirtualQuery failed");
			return FALSE;
		}
	
		int start =  (int)mbi.BaseAddress;
		int end = (int)mbi.BaseAddress+ mbi.RegionSize;
		//get the stack base address by searching the highest address in the allocated memory containing the stack Address
	//	MYINFO("state %08x   %08x",mbi.State,mbi.Type);
		if((mbi.State == MEM_COMMIT || mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE ||  mbi.Type == MEM_PRIVATE) &&
			start <=address && address <= end){
			//MYINFO("Adding start %08x ",(int)mbi.BaseAddress);
			range.StartAddress = start;
			range.EndAddress = end;
			return TRUE;
		}
		else{
			MYERRORE("Address %08x  not inside mapped memory from %08x -> %08x or Type/State not correct ",address,start,end);
			MYINFO("state %08x   %08x",mbi.State,mbi.Type);
			return  FALSE;
		}
		
}

//Adding the ContextData to the generic Memory Ranges
VOID ProcInfo::addContextDataAddress(){
	MemoryRange activationContextData;  
	MemoryRange systemDefaultActivationContextData ;
	MemoryRange pContextData;
	if(getMemoryRange((ADDRINT)peb->ActivationContextData,activationContextData)){
		MYINFO("Init activationContextData base address  %08x -> %08x ",activationContextData.StartAddress,activationContextData.EndAddress);
		genericMemoryRanges.push_back(activationContextData);

	}
	if (getMemoryRange((ADDRINT)peb->SystemDefaultActivationContextData,systemDefaultActivationContextData)){
		MYINFO("Init systemDefaultActivationContextData base address  %08x -> %08x",systemDefaultActivationContextData.StartAddress,systemDefaultActivationContextData.EndAddress);
		genericMemoryRanges.push_back(systemDefaultActivationContextData);
	} 
	if(getMemoryRange((ADDRINT)peb->pContextData,pContextData)){
		MYINFO("Init pContextData base address  %08x -> %08x",pContextData.StartAddress,pContextData.EndAddress);
		genericMemoryRanges.push_back(pContextData);
	}
}

//Adding the SharedMemoryAddress to the generic Memory Ranges
VOID ProcInfo::addSharedMemoryAddress(){
	MemoryRange readOnlySharedMemoryBase;
	if(getMemoryRange((ADDRINT) peb->ReadOnlySharedMemoryBase,readOnlySharedMemoryBase)){
		MYINFO("Init readOnlySharedMemoryBase base address  %08x -> %08x",readOnlySharedMemoryBase.StartAddress,readOnlySharedMemoryBase.EndAddress);
		genericMemoryRanges.push_back(readOnlySharedMemoryBase);
	}

}


//Adding the CodePageDataAddress to the generic Memory Ranges
VOID ProcInfo::addCodePageDataAddress(){
	MemoryRange ansiCodePageData;
	if(getMemoryRange((ADDRINT) peb->AnsiCodePageData,ansiCodePageData)){
		MYINFO("Init ansiCodePageData base address  %08x -> %08x",ansiCodePageData.StartAddress,ansiCodePageData.EndAddress);
		genericMemoryRanges.push_back(ansiCodePageData);
	}
}


//Adding the pShimDataAddress to the generic Memory Ranges
VOID ProcInfo::addpShimDataAddress(){
	MemoryRange pShimData;
	if(getMemoryRange((ADDRINT) peb->pShimData,pShimData)){
		//MYINFO("Init pShimData base address  %08x -> %08x",pShimData.StartAddress,pShimData.EndAddress);
		genericMemoryRanges.push_back(pShimData);
	}
}

//Adding the pShimDataAddress to the generic Memory Ranges
VOID ProcInfo::addpApiSetMapAddress(){
	MemoryRange ApiSetMap;
	if(getMemoryRange((ADDRINT) peb->ApiSetMap,ApiSetMap)){
		//MYINFO("Init ApiSetMap base address  %08x -> %08x",ApiSetMap.StartAddress,ApiSetMap.EndAddress);
		genericMemoryRanges.push_back(ApiSetMap);
	}
}


//Add to the generic memory ranges the KUserShareData structure
VOID ProcInfo::addKUserSharedDataAddress(){
	MemoryRange KUserSharedData;
	KUserSharedData.StartAddress = KUSER_SHARED_DATA_ADDRESS;
	KUserSharedData.EndAddress =KUSER_SHARED_DATA_ADDRESS +KUSER_SHARED_DATA_SIZE;
	genericMemoryRanges.push_back(KUserSharedData);
	
}


//Adding the ProcessHeaps to the generic Memory Ranges
BOOL ProcInfo::addProcessHeapsAndCheckAddress(ADDRINT eip){

	BOOL isEipDiscoveredHere = FALSE;
	/*
	if(!genericMemoryRanges.empty()) {
		genericMemoryRanges.clear();
	}
	*/
	W::SIZE_T BytesToAllocate;
	W::PHANDLE aHeaps;
	//getting the number of ProcessHeaps
	W::DWORD NumberOfHeaps = W::GetProcessHeaps(0, NULL);
    if (NumberOfHeaps == 0) {
		MYERRORE("Error in retrieving number of Process Heaps");
		return isEipDiscoveredHere;
	}
	//Allocating space for the ProcessHeaps Addresses
	W::SIZETMult(NumberOfHeaps, sizeof(*aHeaps), &BytesToAllocate);
	aHeaps = (W::PHANDLE)W::HeapAlloc(W::GetProcessHeap(), 0, BytesToAllocate);
	 if ( aHeaps == NULL) {
		MYERRORE("HeapAlloc failed to allocate space");
		return isEipDiscoveredHere;
	} 

	W::GetProcessHeaps(NumberOfHeaps,aHeaps);
	//Adding the memory range containing the ProcessHeaps to the  genericMemoryRanges
	 for (int i = 0; i < NumberOfHeaps; ++i) {
		MemoryRange processHeap;
		if(getMemoryRange((ADDRINT) aHeaps[i],processHeap)){
			//MYINFO("Init processHeaps base address  %08x -> %08x",processHeap.StartAddress,processHeap.EndAddress);
			genericMemoryRanges.push_back(processHeap);
			if(eip >= processHeap.StartAddress && eip <= processHeap.EndAddress){
				isEipDiscoveredHere = TRUE;
			}
		}
    }
	 
	 MYINFO("Added some heaps@@@@\n");
	 return isEipDiscoveredHere;
}


/*
	Add a section of a module ( for example the .text of the NTDLL ) in order to catch
	writes/reads inside this area
*/
VOID ProcInfo::addProtectedSection(ADDRINT startAddr,ADDRINT endAddr){

	Section s;
	s.begin = startAddr;
	s.end = endAddr;
	s.name = ".text";

	MYINFO("Protected section size is %d\n" , this->protected_section.size());

	protected_section.push_back(s);

	MYINFO("Protected section size is %d\n" , this->protected_section.size());
}

/*
	Check if an address is inside a protected section 
*/
BOOL ProcInfo::isInsideProtectedSection(ADDRINT address){

	//MYINFO("INSIDE PROTECTED SECTION Protected section size is %d\n" , this->protected_section.size());

	for(std::vector<Section>::iterator it = protected_section.begin(); it != protected_section.end(); ++it){
		if(it->begin <= address && address <= it->end){
			return TRUE;
		}
	}

	return FALSE;
}
//------------------------------------------------------------ Current Memory Functions ------------------------------------------------------------

//all memory of the program with pin in its
VOID ProcInfo::enumerateCurrentMemory(){
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0;
	int match_string =0;
	do{
		numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi));
		if((mbi.State == MEM_COMMIT || mbi.State == MEM_MAPPED || mbi.State == MEM_IMAGE) ){
			addCurrentMemoryAddress((ADDRINT)mbi.BaseAddress,mbi.RegionSize);
		}
		MyAddress += mbi.RegionSize;
	}
	while(numBytes);

	return;

}


VOID ProcInfo::addCurrentMemoryAddress(ADDRINT baseAddr,ADDRINT regionSize){
	MemoryRange libItem;
	libItem.StartAddress = baseAddr;
	libItem.EndAddress = baseAddr + regionSize;
	currentMemory.push_back(libItem);

}

void ProcInfo::PrintCurrentMemorydAddr(){
	//Iterate through the already whitelisted memory addresses

	for(std::vector<MemoryRange>::iterator item = currentMemory.begin(); item != currentMemory.end(); ++item) {
		MYPRINT("Current Memory  %08x  ->  %08x",item->StartAddress,item->EndAddress)		;				
	}	

}


//----------------------------------------------- Whitelist Memory Functions -----------------------------------------------


//Add to the the Whitelist array the memory ranges which the process is authorized to read
//NB need to be called AFTER addPebAddress
VOID ProcInfo::enumerateWhiteListMemory(){

	//add stacks to the whitelist
	for(std::vector<MemoryRange>::iterator it = stacks.begin(); it != stacks.end(); ++it){
		addWhitelistAddress(it->StartAddress,it->EndAddress);
	}


	//Add Generic Memory ranges(Shared Memory pages pContextData..)
	for(std::vector<MemoryRange>::iterator item = genericMemoryRanges.begin(); item != genericMemoryRanges.end(); ++item) {
		addWhitelistAddress(item->StartAddress,item->EndAddress);	
	}


	//add mainIMG address to the whitelist
	whiteListMemory.push_back(mainImg);

	
	
	//add Libraries address to the whitelist
	for(std::vector<LibraryItem>::iterator lib = knownLibraries.begin(); lib != knownLibraries.end(); ++lib) {
		addWhitelistAddress(lib->StartAddress,lib->EndAddress);
	}
	for(std::vector<LibraryItem>::iterator lib = unknownLibraries.begin(); lib != unknownLibraries.end(); ++lib) {
		addWhitelistAddress(lib->StartAddress,lib->EndAddress);
	}


	//add teb
	for(std::vector<MemoryRange>::iterator it = tebs.begin(); it != tebs.end(); ++it){
		addWhitelistAddress(it->StartAddress,it->EndAddress);
	}

}


VOID ProcInfo::addWhitelistAddress(ADDRINT baseAddr,ADDRINT endAddress){
	MemoryRange item;
	item.StartAddress = baseAddr;
	item.EndAddress = endAddress;
	whiteListMemory.push_back(item);

}



//merge interval algorithm
//IP1 : the set of intervals is sorted in ascending order
//IP2 : the intervals never overlaps each other (at most the end of the previous is equals at the start of the current)
VOID ProcInfo::mergeMemoryAddresses(){	
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
}

VOID ProcInfo::mergeCurrentMemory(){	
	//get the first element
	std::vector<MemoryRange>::iterator prev_item = currentMemory.begin();
	//start from the second till the end
	for(std::vector<MemoryRange>::iterator item = currentMemory.begin() + 1; item != currentMemory.end(); item++) {
		//if the end of the previous is equal to the start of the current we have tu merge the two interval and delete the previous
		if(item->StartAddress == prev_item->EndAddress){
			item->StartAddress = prev_item->StartAddress;
			//get the new iterator because we have erased an elemment and the old one is broken
			item = currentMemory.erase(prev_item);
		}
		prev_item = item;
	}
}

void ProcInfo::PrintWhiteListedAddr(){
	//Iterate through the already whitelisted memory addresses

	for(std::vector<MemoryRange>::iterator item = genericMemoryRanges.begin(); item != genericMemoryRanges.end(); ++item) {
		MYINFO("[MEMORY RANGE]Whitelisted  %08x  ->  %08x\n",item->StartAddress,item->EndAddress);				
	}

	for(std::vector<HeapZone>::iterator item = this->HeapMap.begin(); item != this->HeapMap.end(); ++item) {
			MYINFO("[HEAPZONES]Whitelisted  %08x  ->  %08x\n",item->begin,item->end);				
	}

	for(std::vector<LibraryItem>::iterator item = this->unknownLibraries.begin(); item != this->unknownLibraries.end(); ++item) {
		MYINFO("[UNKNOWN LIBRARY ITEM]Whitelisted  %08x  ->  %08x\n",item->StartAddress,item->EndAddress);				
	}

	for(std::vector<LibraryItem>::iterator item = this->knownLibraries.begin(); item != this->knownLibraries.end(); ++item) {
		MYINFO("[KNOWN LIBRARY ITEM]Whitelisted  %08x  ->  %08x\n",item->StartAddress,item->EndAddress);				
	}

	for(std::vector<MemoryRange>::iterator item = this->mappedFiles.begin(); item != this->mappedFiles.end(); ++item) {
		MYINFO("[MAPPED FILES]Whitelisted  %08x  ->  %08x\n",item->StartAddress,item->EndAddress);				
	}

	/*
	//iterate through the allocated memory addresses
	for(std::vector<HeapZone>::iterator item = HeapMap.begin(); item != HeapMap.end(); ++item) {
		MYINFO("Whitelisted dynamic %08x  ->  %08x",item->begin,item->end)		;						
	}
	*/
	/*
	for(std::vector<LibraryItem>::iterator lib = LibrarySet.begin(); lib != LibrarySet.end(); ++lib) {
		MYINFO("Whitelisted library %08x  ->  %08x",lib->StartAddress,lib->StartAddress)		;	
	}

	MYINFO("Whitelisted Teb %08x  ->  %08x",tebAddr,  tebAddr + TEB_SIZE );

	MYINFO("Whitelisted Stack %08x  ->  %08x",stackBase - MAX_STACK_SIZE, stackBase);
	*/

}


void ProcInfo::PrintAllMemory(){

	MYPRINT("\nCurrent Memory:");
	this->enumerateCurrentMemory();
	this->mergeCurrentMemory();
	this->PrintCurrentMemorydAddr();
	MYPRINT("\nWhitelist:");
	this->enumerateWhiteListMemory();
	//this->mergeMemoryAddresses();
	this->PrintWhiteListedAddr();
}
