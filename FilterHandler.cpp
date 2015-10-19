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
	MYLOG("Init FilterHandler Teb %x\n",tebAddr);
	//Initializing the Filter map:   "stack" => adding FILTER_STACK to filterExecutionFlag
	initFilterMap();
}


FilterHandler::~FilterHandler(void)
{
}

VOID FilterHandler::initFilterMap(){
	
	filterMap.insert(std::pair<std::string, UINT32>("stack",FilterHandler::FILTER_STACK));
	filterMap.insert(std::pair<std::string, UINT32>("teb",FilterHandler::FILTER_TEB));
}


VOID FilterHandler::setFilters(const string filters){

	vector<string> filterVect;
	stringstream ss(filters);
	string temp;
	while (ss >> temp)
	filterVect.push_back(temp);
	for(std::vector<string>::iterator filt = filterVect.begin(); filt != filterVect.end(); ++filt) {
		
		cout << *filt << "e\n";
		cout << "current value to add "<<  filterMap[*filt]<< "\n";
		filterExecutionFlag += pow(2.0,filterMap[*filt]);
		cout << "current flag "<< filterExecutionFlag<< "\n";
	}

	cout << "Trying Stack " << (1<<FilterHandler::FILTER_STACK) << " and "<< filterExecutionFlag << "  = " <<	(1<<FilterHandler::FILTER_STACK & filterExecutionFlag) ; ;
	
}

//initializing the base stack address
VOID FilterHandler::setStackBase(ADDRINT addr){
	//hasn't been already initialized
	if(stackBase == 0) {	
		stackBase = addr;
		MYLOG("(FILTERHANDLER)Init FilterHandler Stack from %x to %x\n",stackBase+STACK_BASE_PADDING,stackBase -MAX_STACK_SIZE);
	}	
}

VOID FilterHandler::addLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr){
	LibraryItem libItem;
	libItem.StartAddress = startAddr;
	libItem.EndAddress = endAddr;
	libItem.name = name;
	LibrarySet.push_back(libItem);
	MYLOG("(FILTERHANDLER)Add Library Lib %s\n",libToString(libItem));
	return ;
}

VOID  FilterHandler::showFilteredLibs(){
	for(std::vector<LibraryItem>::iterator lib = LibrarySet.begin(); lib != LibrarySet.end(); ++lib) {
		MYLOG("(FILTERHANDLER)Filtered Lib %s\n",libToString(*lib));
	}
}

string FilterHandler::libToString(LibraryItem lib){
	std::stringstream ss;
	ss << "Library: " <<lib.name;
	ss << "\t\tstart: " << std::hex << lib.StartAddress;
	ss << "\tend: " << std::hex << lib.EndAddress;
	const std::string s = ss.str();	
	return s;
	
}

BOOL FilterHandler::isKnownLibrary(const string name){
	//TODO return true if this is a know windows dll
	return TRUE;
}

//Wrapper aroud the different function which check if address belong to the filtered address space
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



/*check if the address belong to a Library */
//TODO add a whiitelist of Windows libraries that will be loaded
BOOL FilterHandler::isLibraryInstruction(ADDRINT address){
	PIN_LockClient();
	IMG curImg = IMG_FindByAddress(address);
	PIN_UnlockClient();

	if (IMG_Valid (curImg) && !IMG_IsMainExecutable(curImg)){
		return TRUE;
	}
	return FALSE;

}
