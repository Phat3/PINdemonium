#include "FilterHandler.h"

//singleton
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
	filtered_library_name.push_back("GDI32.dll");
	filtered_library_name.push_back("LPK.dll");
	filtered_library_name.push_back("USP10.dll");
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
	MYINFO("Setting write filters" );
	vector<string> filterVect;
	stringstream ss(filters);
	string temp;
	while (ss >> temp){
		filterVect.push_back(temp);
	}
	for(std::vector<string>::iterator filt = filterVect.begin(); filt != filterVect.end(); ++filt) {	
		MYINFO("Activating filter %s",(*filt).c_str() );
		filterExecutionFlag += pow(2.0,filterMap[*filt]); //bitmap representing active flags
	}	   	
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
		return (pInfo->isStackAddress(addr) && pInfo->isLibraryInstruction(eip));
}


BOOL FilterHandler::IsNameInFilteredArray(std::string img_name){
	for(std::vector<string>::iterator name = this->filtered_library_name.begin(); name != filtered_library_name.end(); ++name){
		if(img_name.find(name->c_str()) != std::string::npos ){
			this->filtered_library_name.erase(name); // WARNING-> SIDE EFFECT: remove the element from the name of the library filtered ( brute optimization: basically when we have registered the filtered library in the filtered_library vector we can avoid to re-check another time the name )
			return TRUE;
		} 
	}
	return FALSE;
}

BOOL FilterHandler::isFilteredLibraryInstruction(ADDRINT eip){
	for(std::vector<LibraryItem>::iterator lib = this->filtered_libray.begin(); lib != this->filtered_libray.end(); ++lib){
		if(eip >= lib->StartAddress && eip <= lib->EndAddress){
			return TRUE;
		}
	}
	return FALSE;
}


void FilterHandler::addToFilteredLibrary(std::string name , ADDRINT start_addr , ADDRINT end_addr){	
	LibraryItem li;
	li.StartAddress = start_addr;
	li.EndAddress = end_addr;
	li.name = name;	
	this->filtered_libray.push_back(li);
	MYINFO("filtered library size is %d\n" , this->filtered_libray.size());
}






