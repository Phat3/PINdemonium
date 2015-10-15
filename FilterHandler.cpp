#include "FilterHandler.h"
#include "Debug.h"
#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream, std::stringbuf

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
	//Initializing the TEB
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
		MYINFO("(FILTERHANDLER)Init FilterHandler Stack from %x to %x\n",stackBase+STACK_BASE_PADDING,stackBase -MAX_STACK_SIZE);
	}	
}

VOID FilterHandler::addLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr){
	LibraryItem libItem;
	libItem.StartAddress = startAddr;
	libItem.EndAddress = endAddr;
	libItem.name = name;
	LibrarySet.push_back(libItem);
	MYINFO("(FILTERHANDLER)Add Library Lib %s\n",libToString(libItem));
	return ;
}

VOID  FilterHandler::showFilteredLibs(){
	for(std::vector<LibraryItem>::iterator lib = LibrarySet.begin(); lib != LibrarySet.end(); ++lib) {
		MYINFO("(FILTERHANDLER)Filtered Lib %s\n",libToString(*lib));
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
BOOL FilterHandler::isFilteredWrite(ADDRINT addr){
	return isTEBWrite(addr) || isStackWrite(addr);
}

//Check if the addr belongs to the TEB
BOOL FilterHandler::isTEBWrite(ADDRINT addr){
	return (tebAddr <= addr && addr <= tebAddr + TEB_SIZE );
}

//Check if addr belong to the Stack
BOOL FilterHandler::isStackWrite(ADDRINT addr){	
	//MYINFO("(FILTERHANDLER)addr %x stackBase %x  endstack  %x\n",addr,stackBase + STACK_BASE_PADDING, stackBase - MAX_STACK_SIZE);
	return (stackBase - MAX_STACK_SIZE < addr && addr < stackBase +STACK_BASE_PADDING);
}

//check if the address belong to a Library
//TODO add a whiitelist of Windows libraries that will be loaded
BOOL FilterHandler::isLibraryInstruction(ADDRINT address){
	IMG curImg = IMG_FindByAddress(address);
	if (IMG_Valid (curImg) && !IMG_IsMainExecutable(curImg)){
		return TRUE;
	}
	return FALSE;

}
