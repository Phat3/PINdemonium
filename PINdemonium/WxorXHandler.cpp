#include "WxorXHandler.h"


WxorXHandler* WxorXHandler::instance = 0;

WxorXHandler* WxorXHandler::getInstance()
{
	if (instance == 0)
		instance = new WxorXHandler();
	return instance;
}

WxorXHandler::WxorXHandler(){
	this->pid = W::GetCurrentProcessId();
	this->WriteSetContainer.insert(std::pair<W::DWORD,std::vector<WriteInterval>>(this->pid, std::vector<WriteInterval>()));
	
}

WxorXHandler::~WxorXHandler(void)
{
}



//----------------------- PUBLIC METHODS -----------------------

//check if the current instruction is a write instruction
BOOL WxorXHandler::isWriteINS(INS ins){
	return INS_IsMemoryWrite(ins);
}


// - Calculate the target of the write (end_addr)
// - Update an existing WriteInterval / create a new one
VOID WxorXHandler::writeSetManager(ADDRINT start_addr, UINT32 size){
	std::vector<WriteInterval> &currentWriteSet = this->WriteSetContainer.at(this->pid);
	this->_writeSetManager(start_addr,size,currentWriteSet);
	
}

//return the WriteItem index inside our vector that broke the W xor X index
WriteInterval* WxorXHandler::getWxorXinterval(ADDRINT ip){
	std::vector<WriteInterval> &currentWriteSet = this->WriteSetContainer.at(this->pid);
	return this->_getWxorXinterval(ip,currentWriteSet);	
	
}

// - Calculate the target of the write (end_addr)
// - Update an existing WriteInterval / create a new one
VOID WxorXHandler::writeSetManager( ADDRINT start_addr, UINT32 size,W::DWORD cur_pid){
	
		std::vector<WriteInterval> &currentWriteSet = this->WriteSetContainer[cur_pid];
		this->_writeSetManager(start_addr,size,currentWriteSet);

	
	
}

//return the WriteItem index inside our vector that broke the W xor X index
std::vector<WriteInterval>& WxorXHandler::getWxorXintervalInjected(W::DWORD pid){
	std::vector<WriteInterval> &currentWriteSet = this->WriteSetContainer[pid];
	return currentWriteSet;

}




VOID WxorXHandler::incrementCurrJMPNumber(int writeItemIndex){
	std::vector<WriteInterval> &currentWriteSet = this->WriteSetContainer.at(this->pid);
	currentWriteSet[writeItemIndex].incrementCurrNumberJMP();
}


//Clear the currentWriteSet for injection in pid different from current programs 
VOID WxorXHandler::clearWriteSet(W::DWORD pid){
	if(pid != this->pid){
		WriteSetContainer[pid] = std::vector<WriteInterval>();
	}

}

VOID WxorXHandler::displayWriteSet(W::DWORD pid){	
	std::vector<WriteInterval> &currentWriteSet = this->WriteSetContainer.at(pid);
	for(unsigned index=0; index <  currentWriteSet.size(); index++) {
		MYINFO("WriteInterval number %u  start %08x end %08x",index,currentWriteSet.at(index).getAddrBegin(),currentWriteSet.at(index).getAddrEnd());
	}
}


//----------------------- PRIVATES METHODS -----------------------

VOID WxorXHandler::_writeSetManager( ADDRINT start_addr, UINT32 size,std::vector<WriteInterval> &currentWriteSet){
	//check if the write is on the heap
	bool isheap = ProcInfo::getInstance()->searchHeapMap(start_addr);

	//calculate the end address of the write
	UINT32 end_addr = start_addr + size;
	//iterate through our structure in order to find if we have to update one of our WriteInterval
	//We can't use an iterator because, after a certain amount of writeinterval, it will broke
	for(int i = 0; i < currentWriteSet.size(); i++){
		//if we foud that an item has to be updated then update it and return
		if(currentWriteSet[i].checkUpdate(start_addr, end_addr)){
			currentWriteSet[i].update(start_addr, end_addr, isheap);	
			return; 
		}
	}
	//create and add it to our structure
	WriteInterval new_interval = WriteInterval(start_addr, end_addr, isheap);
	currentWriteSet.push_back(new_interval);
}


WriteInterval* WxorXHandler::_getWxorXinterval(ADDRINT ip,std::vector<WriteInterval> &currentWriteSet){
	//iterate through our structure in order to find if we have a violation of the W xor X law
	for(std::vector<WriteInterval>::iterator item = currentWriteSet.begin(); item != currentWriteSet.end(); ++item) {
		//if we found that the current ip is in a memory area that was previously written
		//we have to return the address of the WriteInterval that has to be analyzed by our heuristics
		if(item->checkInside(ip)){
			return &(*item);
		}
	}
	//otherwise return -1 (the law is not broke)
	return NULL;

}