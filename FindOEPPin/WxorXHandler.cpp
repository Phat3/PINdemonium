#include "WxorXHandler.h"


WxorXHandler* WxorXHandler::instance = 0;

WxorXHandler* WxorXHandler::getInstance()
{
	if (instance == 0)
		instance = new WxorXHandler;
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

	//calculate the end address of the write
	UINT32 end_addr = start_addr + size;
	//iterate through our structure in order to find if we have to update one of our WriteInterval
	for(std::vector<WriteInterval>::iterator item = this->WritesSet.begin(); item != this->WritesSet.end(); ++item) {
		//if we foud that an item has to be updated then update it and return
		if(item->checkUpdate(start_addr, end_addr)){
			item->update(start_addr, end_addr);	
			return;
		}
	}
	//otherwise create a new WriteInterval object and add it to our structure
	WriteInterval new_interval(start_addr, end_addr);
	WritesSet.push_back(new_interval);

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



//Why this crash the porgram with UPX?
VOID WxorXHandler::displayWriteSet(){
	
	for(unsigned index=0; index <  this->WritesSet.size(); index++) {
		MYINFO("WriteInterval number %d  start %08x eend %08x",index,this->WritesSet.at(index).getAddrBegin(),this->WritesSet.at(index).getAddrEnd());
	}
	/*
	int i = 0;y doesn't WORK?
	for(std::vector<WriteInterval>::iterator item = this->WritesSet.begin(); item != this->WritesSet.end(); ++item) {

		MYINFO("WriteInterval number %d  start %08x eend %08x",i,item->getAddrBegin(),item->getAddrEnd());
		i++;
	}
	*/
	
	
}