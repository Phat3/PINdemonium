#include "FilterHandler.h"
#include "Debug.h"
namespace W {
	#include <Windows.h>
}

#define MAX_STACK_SIZE 0x5000    //Used to define the memory range of the stack
#define STACK_BASE_PADDING 0x500 //needed because the stack pointer given by pin is not the highest one
#define TEB_SIZE 0xf28

FilterHandler* FilterHandler::instance = 0;


		
FilterHandler* FilterHandler::getInstance()
{
	if (instance == 0){	
		instance = new FilterHandler;

	}
	return instance;
}

FilterHandler::FilterHandler(){
	char *tebStr=(char *)malloc(16); 
	W::_TEB *teb = W::NtCurrentTeb();
	sprintf(tebStr,"%x",teb);
	tebAddr = strtoul(tebStr,NULL,16);
	MYINFO("Init FilterHandler Teb %x\n",tebAddr);
}


FilterHandler::~FilterHandler(void)
{
}

VOID FilterHandler::setStackBase(ADDRINT addr){
	//hasn't been already initialized
	if(stackBase == 0) {	
		stackBase = addr;
		MYINFO("Init FilterHandler Stack from %x to %x",stackBase+STACK_BASE_PADDING,stackBase -MAX_STACK_SIZE);
	}	
}

BOOL FilterHandler::isFilteredWrite(ADDRINT addr){
	return isTEBWrite(addr) || isStackWrite(addr);
}

BOOL FilterHandler::isTEBWrite(ADDRINT addr){
	return (tebAddr <= addr && addr <= tebAddr + TEB_SIZE );
}

BOOL FilterHandler::isStackWrite(ADDRINT addr){	
	MYINFO("addr %x stackBase %x  endstack  %x\n",addr,stackBase + STACK_BASE_PADDING, stackBase - MAX_STACK_SIZE);
	return (stackBase - MAX_STACK_SIZE < addr && addr < stackBase +STACK_BASE_PADDING);
}

//check if the address belong to a Library
//TODO add a whiitelist of Windows libraries that will be loaded
BOOL FilterHandler::isKnownLibInstruction(ADDRINT address){
	IMG curImg = IMG_FindByAddress(address);
	if (IMG_Valid (curImg) && !IMG_IsMainExecutable(curImg)){
		return TRUE;
	}
	return FALSE;

}
