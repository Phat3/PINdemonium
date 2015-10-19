#include "FilterHandler.h"
#include "math.h"
#include "Log.h"
namespace W {
	#include <Windows.h>
}

FilterHandler* FilterHandler::instance = 0;


FilterHandler* FilterHandler::getInstance()
{
	if (instance == 0){	
		instance = new FilterHandler;

	}
	return instance;
}

FilterHandler::FilterHandler(){
	//Initializing the TEB
	char *tebStr=(char *)malloc(16); 
	W::_TEB *teb = W::NtCurrentTeb();
	sprintf(tebStr,"%x",teb);
	tebAddr = strtoul(tebStr,NULL,16);
	MYLOG("(FILTERHANDLER)Init FilterHandler Teb %x\n",tebAddr);
	//Initializing the Filter map:   "stack" => adding FILTER_STACK to filterExecutionFlag
	initFilterMap();
}


FilterHandler::~FilterHandler(void)
{
}

/**
Initialize the hashmap between string representing the filter type and the flag used to activate the filter
**/
VOID FilterHandler::initFilterMap(){	
	filterMap.insert(std::pair<std::string, UINT32>("stack",FilterHandler::FILTER_STACK));
	filterMap.insert(std::pair<std::string, UINT32>("teb",FilterHandler::FILTER_TEB));
}


/**
Set the filter which will be activated
stack: filter all instructions which belong to libraries and write on the stack
teb:   filter all instructions which belong to libraries and write on the TEB (Exception Handling)
**/
VOID FilterHandler::setFilters(const string filters){

	vector<string> filterVect;
	stringstream ss(filters);
	string temp;
	while (ss >> temp)
	filterVect.push_back(temp);
	for(std::vector<string>::iterator filt = filterVect.begin(); filt != filterVect.end(); ++filt) {	
		MYLOG("(FILTERHANDLER)Activating filter %s\n",(*filt).c_str() );
		filterExecutionFlag += pow(2.0,filterMap[*filt]);
	//	MYLOG("(FILTERHANDLER)Current flag %d \n",filterExecutionFlag);
	}	   
	//MYLOG("(FILTERHANDLER)Trying Stack %d and FilterExecutionFlag %d  active %d \n",(1<<FilterHandler::FILTER_STACK) ,filterExecutionFlag ,	(1<<FilterHandler::FILTER_STACK & filterExecutionFlag)) ;
	
}

/**
Initializing the base stack address
**/
VOID FilterHandler::setStackBase(ADDRINT addr){
	//hasn't been already initialized
	if(stackBase == 0) {	
		stackBase = addr;
		MYLOG("(FILTERHANDLER)Init FilterHandler Stack from %x to %x\n",stackBase+STACK_BASE_PADDING,stackBase -MAX_STACK_SIZE);
	}	
}


/**
Display on the log the currently filtered libs
**/
VOID  FilterHandler::showFilteredLibs(){
	for(std::vector<LibraryItem>::iterator lib = LibrarySet.begin(); lib != LibrarySet.end(); ++lib) {
		MYLOG("(FILTERHANDLER)Filtered Lib %s\n",libToString(*lib));
	}
}

/**
Convert a LibraryItem object to string
**/
string FilterHandler::libToString(LibraryItem lib){
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
BOOL FilterHandler::isKnownLibrary(const string name){
	//TODO return true if this is a know windows dll
	return TRUE;
}

/**
Check if the instuction at "eip" which writes at "addr" is filtered based on the active filters(i.e. stack,teb)
**/
BOOL FilterHandler::isFilteredWrite(ADDRINT addr, ADDRINT eip){
	
	return ((1<<FilterHandler::FILTER_TEB & filterExecutionFlag) && isLibTEBWrite(addr,eip) )   ||
		   ((1<<FilterHandler::FILTER_STACK & filterExecutionFlag) && isLibStackWrite(addr,eip));
		   
}

//Check if the addr belongs to the TEB
BOOL FilterHandler::isLibTEBWrite(ADDRINT addr,ADDRINT eip){
	//MYINFO("[FILTERHANDLER]Calling isTEBWrite\n");
	return (tebAddr <= addr && addr <= tebAddr + TEB_SIZE ) && isLibraryInstruction(eip);
}



//Check if the write addr belongs to the Stack and the current eip is not in the libraries
BOOL FilterHandler::isLibStackWrite(ADDRINT addr,ADDRINT eip){	
	//MYINFO("[FILTERHANDLER]Calling isStackWrite\n");
	return (stackBase - MAX_STACK_SIZE < addr && addr < stackBase +STACK_BASE_PADDING) && isLibraryInstruction(eip);
}

VOID FilterHandler::addLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr){
	LibraryItem libItem;
	libItem.StartAddress = startAddr;
	libItem.EndAddress = endAddr;
	libItem.name = name;
	if (LibrarySet.empty()) {
		LibrarySet.push_back(libItem);
		MYINFO("(FILTERHANDLER)Add Library Lib %s\n",libToString(libItem));
		return;
	}
	for(auto lib = LibrarySet.begin(); lib != LibrarySet.end(); ++lib) {
		if (lib->StartAddress < startAddr) {
			MYINFO("------------------------(FILTERHANDLER)Add Library Lib %s\n",libToString(libItem));
			LibrarySet.insert(lib, libItem);
			return;
		}
	}
	LibrarySet.push_back(libItem);
	MYINFO("+++++++++++++++++++++++++(FILTERHANDLER)Add Library Lib %s\n",libToString(libItem));
	return ;
}

BOOL FilterHandler::binarySearch (int start, int end, ADDRINT value) {
	if (start > end)
		return FALSE;
	if (start == end) {
		if(LibrarySet.at(floor(double(end+start)/2)).StartAddress <= value && value <= LibrarySet.at(floor(double(end+start)/2)).EndAddress)
			return TRUE;
		else
			return FALSE;
	}
	if(LibrarySet.at(floor(double(end+start)/2)).StartAddress <= value && value <= LibrarySet.at(floor(double(end+start)/2)).EndAddress)
		return TRUE;
	else {
		BOOL result1 = FilterHandler::binarySearch (start, floor(double(end+start)/2), value);
		BOOL result2 = FilterHandler::binarySearch (start, floor(double(end+start)/2), value);
		return result1 & result2;
	}
}

/*check if the address belong to a Library */
//TODO add a whiitelist of Windows libraries that will be loaded
BOOL FilterHandler::isLibraryInstruction(ADDRINT address){
	/*	
	if (binarySearch(0, LibrarySet.size() - 1, address)){
		//MYLOG("Instruction at %x filtered \n", address);
		return TRUE;
	}
	return FALSE;
	*/

for(std::vector<LibraryItem>::iterator lib = LibrarySet.begin(); lib != LibrarySet.end(); ++lib) {
		if (lib->StartAddress <= address && address <= lib->EndAddress)
		//	MYLOG("Instruction at %x filtered \n", address);
			return TRUE;
	}
	
	return FALSE;
/*	
	
	PIN_LockClient();
	IMG curImg = IMG_FindByAddress(address);
	PIN_UnlockClient();
	if (IMG_Valid (curImg) && !IMG_IsMainExecutable(curImg)){
		return TRUE;
	}
	return FALSE;
	
*/
}
