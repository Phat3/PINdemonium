#include "WxorXHandler.h"


WxorXHandler* WxorXHandler::instance = 0;

WxorXHandler* WxorXHandler::getInstance()
{
	if (instance == 0)
		instance = new WxorXHandler();
	return instance;
}

WxorXHandler::~WxorXHandler(void)
{
}


//----------------------- GETTER / SETTER -----------------------

std::vector<WriteInterval> WxorXHandler::getWritesSet(){
	return this->WritesSet;
}


//----------------------- PUBLIC METHODS -----------------------

//check if the current instruction is a write instruction
BOOL WxorXHandler::isWriteINS(INS ins){
	return INS_IsMemoryWrite(ins);
}

// - Calculate the target of the write (end_addr)
// - Update an existing WriteInterval / create a new one
VOID WxorXHandler::writeSetManager(ADDRINT ip, ADDRINT start_addr, UINT32 size){
	
	//check if the write is on the heap
	bool isheap = ProcInfo::getInstance()->searchHeapMap(start_addr);

	//calculate the end address of the write
	UINT32 end_addr = start_addr + size;
	//iterate through our structure in order to find if we have to update one of our WriteInterval
	//We can't use an iterator because, after a certain amount of writeinterval, it will broke
	for(int i = 0; i < this->WritesSet.size(); i++){
		//if we foud that an item has to be updated then update it and return
		if(this->WritesSet[i].checkUpdate(start_addr, end_addr)){
			this->WritesSet[i].update(start_addr, end_addr, isheap);	
			return; 
		}
	}
	//create and add it to our structure
	WriteInterval new_interval = WriteInterval(start_addr, end_addr, isheap);
	this->WritesSet.push_back(new_interval);
}

//return the WriteItem index inside our vector that broke the W xor X index
UINT32 WxorXHandler::getWxorXindex(ADDRINT ip){
	//iterate through our structure in order to find if we have a violation of the W xor X law
	for(std::vector<WriteInterval>::iterator item = this->WritesSet.begin(); item != this->WritesSet.end(); ++item) {
		//if we found that the current ip is in a memory area that was previously written
		//we have to return the address of the WriteInterval that has to be analyzed by our heuristics
		if(item->checkInside(ip)){
			int index = item - WritesSet.begin();
			return index;
		}
	}
	//otherwise return -1 (the law is not broke)
	return -1;
}

//delete the analyzed WriteInterval
VOID WxorXHandler::deleteWriteItem(UINT32 writeItemIndex){
	this->WritesSet.erase(this->WritesSet.begin() + writeItemIndex);
}

VOID WxorXHandler::setBrokenFlag(int writeItemIndex){
	this->WritesSet[writeItemIndex].setBrokenFlag(true);
}

VOID WxorXHandler::incrementCurrJMPNumber(int writeItemIndex){
	this->WritesSet[writeItemIndex].incrementCurrNumberJMP();
}

//Why this crash the porgram with UPX?
VOID WxorXHandler::displayWriteSet(){	
	for(unsigned index=0; index <  this->WritesSet.size(); index++) {
		MYINFO("WriteInterval number %u  start %08x end %08x",index,this->WritesSet.at(index).getAddrBegin(),this->WritesSet.at(index).getAddrEnd());
	}
}