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

ADDRINT ProcInfo::getPINVMStart(){
	return this->PinVMDll.StartAddress;
}

ADDRINT ProcInfo::getPINVMEnd(){
	return this->PinVMDll.EndAddress;
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

void ProcInfo::printHeapList(){
	for(unsigned index=0; index <  this->HeapMap.size(); index++) {
		MYINFO("Heapzone number  %d  start %08x end %08x",index,this->HeapMap.at(index).begin,this->HeapMap.at(index).end);
	}
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



// This code belongs to the TitanEngine framework http://www.reversinglabs.com/products/TitanEngine.php
long long ProcInfo::FindEx(W::HANDLE hProcess, W::LPVOID MemoryStart, W::DWORD MemorySize, W::LPVOID SearchPattern, W::DWORD PatternSize, W::LPBYTE WildCard){

	int i = NULL;
	int j = NULL;
	W::ULONG_PTR Return = NULL;
	W::LPVOID ueReadBuffer = NULL;
	W::PUCHAR SearchBuffer = NULL;
	W::PUCHAR CompareBuffer = NULL;
	W::ULONG_PTR ueNumberOfBytesRead = NULL;
	W::LPVOID currentSearchPosition = NULL;
	W::DWORD currentSizeOfSearch = NULL;
	W::BYTE nWildCard = NULL;

	if(WildCard == NULL){WildCard = &nWildCard;}
	if(hProcess != NULL && MemoryStart != NULL && MemorySize != NULL){
		if(hProcess != W::GetCurrentProcess()){
			ueReadBuffer = W::VirtualAlloc(NULL, MemorySize, MEM_COMMIT, PAGE_READWRITE);
			if(!W::ReadProcessMemory(hProcess, MemoryStart, ueReadBuffer, MemorySize, &ueNumberOfBytesRead)){
				W::VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
				return(NULL);
			}else{
				SearchBuffer = (W::PUCHAR)ueReadBuffer;
			}
		}else{
			SearchBuffer = (W::PUCHAR)MemoryStart;
		}
		__try{
			CompareBuffer = (W::PUCHAR)SearchPattern;
			for(i = 0; i < (int)MemorySize && Return == NULL; i++){
				for(j = 0; j < (int)PatternSize; j++){
					if(CompareBuffer[j] != *(W::PUCHAR)WildCard && SearchBuffer[i + j] != CompareBuffer[j]){
						break;
					}
				}
				if(j == (int)PatternSize){
					Return = (W::ULONG_PTR)MemoryStart + i;
				}
			}
			W::VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
			return(Return);
		}__except(EXCEPTION_EXECUTE_HANDLER){
			W::VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
			return(NULL);
		}
	}else{
		return(NULL);
	}
}

VOID ProcInfo::SearchPinVMDll()
{
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0;
	int find =0;

	do
	{
		numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi));
		
		if((mbi.State == MEM_COMMIT) && (mbi.Protect == PAGE_EXECUTE_READ | mbi.Protect == PAGE_READONLY))
		{
			MYINFO("\n\n---------\n");
			MYINFO("Allocation Base: %x\n", mbi.AllocationBase);
			MYINFO("BaseAddress: %x\n", mbi.BaseAddress);
			MYINFO("Size: %x\n", mbi.RegionSize);

			find = FindEx(W::GetCurrentProcess(),mbi.BaseAddress,mbi.RegionSize, "@CHARM", strlen("@CHARM"), NULL);
			//Check if the string to identify the pinvm.dll is found
			if(find){ 
			
				PinVMDll.name = "pinvm.dll";
				PinVMDll.StartAddress = (ADDRINT)mbi.AllocationBase;
				PinVMDll.EndAddress = (ADDRINT)mbi.BaseAddress + (ADDRINT)mbi.RegionSize;
				MYINFO("FOUND PINVMDLL in %x\n",mbi.BaseAddress);
			}
			//Enlarge the PinVMDll size
			else if((ADDRINT)mbi.AllocationBase == PinVMDll.StartAddress){
				PinVMDll.EndAddress = (ADDRINT)mbi.BaseAddress + (ADDRINT)mbi.RegionSize;
			}
		}

		MyAddress += mbi.RegionSize;

	}
	while(numBytes);
	MYINFO("PinVM DLL start: %x end: %x",PinVMDll.StartAddress,PinVMDll.EndAddress);

	return;
}