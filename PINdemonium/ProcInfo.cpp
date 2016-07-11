#include "ProcInfo.h"

// singleton
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
	exe_name = Helper::replace_string(exe_name, " ", "");
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

// print the sections information in a fancy way
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

// insert the mmory range in the current list of memory ranges detected on the heap
void ProcInfo::insertHeapZone(HeapZone heap_zone){
	this->HeapMap.push_back(heap_zone);
}

// remove last memory range from the heap list
void ProcInfo::removeLastHeapZone(){
	this->HeapMap.pop_back();
}

// remove a specific memory range from the heap list
void ProcInfo::deleteHeapZone(UINT32 index){     
	this->HeapMap.erase(this->HeapMap.begin()+index);
}

// return the index of he memory range that includes the specified address
// if it is not found it returns -1
UINT32 ProcInfo::searchHeapMap(ADDRINT ip){
	int i=0;
	HeapZone hz;
	for(i=0; i<this->HeapMap.size();i++){	    
		hz = this->HeapMap.at(i);
		if(ip >= hz.begin && ip <= hz.end){
			   return i;
		}
	}
	return -1;
}

//return the heapzone object
HeapZone* ProcInfo::getHeapZoneByIndex(UINT32 index){
	return &this->HeapMap.at(index);
}


//return the entropy value of the entire program
float ProcInfo::GetEntropy(){
	IMG binary_image = APP_ImgHead();
	// trick in order to convert a ln in log2
	const double d1log2 = 1.4426950408889634073599246810023;
	double Entropy = 0.0;
	unsigned long Entries[256];
	unsigned char* Buffer;
	//calculate the entropy only on the main module address space
	ADDRINT start_address = IMG_LowAddress(binary_image);
	ADDRINT end_address = IMG_HighAddress(binary_image);
	UINT32 size = end_address - start_address;
	// copy the main module in a buffer in order to analyze it
	Buffer = (unsigned char *)malloc(size);
	PIN_SafeCopy(Buffer , (void const *)start_address , size);
	// set to all zero the matrix of the bytes occurrence
	memset(Entries, 0, sizeof(unsigned long) * 256);
	// increment the counter of the current read byte (Buffer[i])in the occurence matrix (Entries)
	for (unsigned long i = 0; i < size; i++)
		Entries[Buffer[i]]++;
	// do the shannon formula on the occurence matrix ( H = sum(P(i)*log2(P(i)) )
	for (unsigned long i = 0; i < 256; i++)
	{
		double Temp = (double) Entries[i] / (double) size;
		if (Temp > 0)
			Entropy += - Temp*(log(Temp)*d1log2); 
	}
	return Entropy;
}

// 
void ProcInfo::insertInJmpBlacklist(ADDRINT ip){
	this->addr_jmp_blacklist.insert(ip);
}

BOOL ProcInfo::isInsideJmpBlacklist(ADDRINT ip){
	return this->addr_jmp_blacklist.find(ip) != this->addr_jmp_blacklist.end();
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



//+++++++++++++++++++++++++++++++++++++++++++++++++++++++ Memory layout information +++++++++++++++++++++++++++++++++++++++++++++++++++++++

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
		}
		return;	
	}
	else{
		//check if the library is present yet in the list of unknownLibraries
		if(!isLibItemDuplicate(startAddr , unknownLibraries)){
			unknownLibraries.push_back(libItem);
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
}

/*check if the address belong to a Library */
//TODO add a whiitelist of Windows libraries that will be loaded
BOOL ProcInfo::isLibraryInstruction(ADDRINT address){	 
	//check inside known libraries
	for(std::vector<LibraryItem>::iterator lib = knownLibraries.begin(); lib != knownLibraries.end(); ++lib) {
		if (lib->StartAddress <= address && address <= lib->EndAddress){
		return TRUE;}
	}
	//check inside unknown libraries
	for(std::vector<LibraryItem>::iterator lib = unknownLibraries.begin(); lib != unknownLibraries.end(); ++lib) {
		if (lib->StartAddress <= address && address <= lib->EndAddress){
			return TRUE;   
		}
	}
	return FALSE;	
}

BOOL ProcInfo::isKnownLibraryInstruction(ADDRINT address){
	//check inside known libraries
	for(std::vector<LibraryItem>::iterator lib = knownLibraries.begin(); lib != knownLibraries.end(); ++lib) {
		if (lib->StartAddress <= address && address <= lib->EndAddress)
			return TRUE;
	}
	return FALSE;	
}

// bootstrap memory information
void ProcInfo::addProcAddresses(){
	addPebAddress();
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
	MYINFO("PEB added from %08x -> %08x",peb,peb+sizeof(PEB));
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
	MemoryRange cur_teb;
	cur_teb.StartAddress = (ADDRINT)tebAddr;
	cur_teb.EndAddress = (ADDRINT)tebAddr +TEB_SIZE;
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
	if((mbi.State == MEM_COMMIT || mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE ||  mbi.Type == MEM_PRIVATE) &&
		start <=address && address <= end){
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


//Adding the ProcessHeaps to the generic Memory Ranges
BOOL ProcInfo::addProcessHeapsAndCheckAddress(ADDRINT eip){
	BOOL isEipDiscoveredHere = FALSE;
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
			genericMemoryRanges.push_back(processHeap);
			if(eip >= processHeap.StartAddress && eip <= processHeap.EndAddress){
				isEipDiscoveredHere = TRUE;
			}
		}
    }
	return isEipDiscoveredHere;
}





