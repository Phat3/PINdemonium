#include "LibraryHandler.h"
#include "Debug.h"


LibraryHandler::LibraryHandler(void)
{
}


LibraryHandler::~LibraryHandler(void)
{
}

BOOL LibraryHandler::checkWriteInExeSpace(ADDRINT eip){
	return TRUE;
}

//Mock instruction
BOOL LibraryHandler::isLibInstruction(ADDRINT eip){
	
	IMG curImg = IMG_FindByAddress(eip);
	if (IMG_Type(curImg) == IMG_TYPE_SHAREDLIB){
		return TRUE;
	}
	return FALSE;

}
