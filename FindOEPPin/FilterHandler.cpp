#include "FilterHandler.h"

FilterHandler* FilterHandler::instance = 0;


FilterHandler* FilterHandler::getInstance()
{
	if (instance == 0){	
		instance = new FilterHandler;

	}
	return instance;
}

FilterHandler::FilterHandler(){
	pInfo = ProcInfo::getInstance();


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
		MYINFO("Activating filter %s",(*filt).c_str() );
		filterExecutionFlag += pow(2.0,filterMap[*filt]);
	//	MYINFO("Current flag %d ",filterExecutionFlag);
	}	   
	//MYINFO("Trying Stack %d and FilterExecutionFlag %d  active %d ",(1<<FilterHandler::FILTER_STACK) ,filterExecutionFlag ,	(1<<FilterHandler::FILTER_STACK & filterExecutionFlag)) ;
	
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
	//MYINFO("Calling isTEBWrite");
	return (pInfo->isTebAddress(addr) && pInfo->isLibraryInstruction(eip));
}


//Check if the write addr belongs to the Stack and the current eip is not in the libraries
BOOL FilterHandler::isLibStackWrite(ADDRINT addr,ADDRINT eip){	
	
	//MYINFO("Calling isStackWrite");
	return (pInfo->isStackAddress(addr) && 
		pInfo->isLibraryInstruction(eip));
}





