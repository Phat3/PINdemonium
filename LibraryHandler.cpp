#include "LibraryHandler.h"


LibraryHandler::LibraryHandler(void)
{
}


LibraryHandler::~LibraryHandler(void)
{
}

//Mock instruction
BOOL LibraryHandler::filterLib(ADDRINT eip){
	if(eip>0x00420000){
		return TRUE;
	}
	return FALSE;
}
