#include "LibraryHandler.h"
#include "Debug.h"




LibraryHandler::~LibraryHandler(void)
{
}

BOOL LibraryHandler::isStackWrite(INS ins){
	return INS_IsStackWrite	(ins); 	
}

//check if the address belong to a Library
//TODO add a whiitelist of Windows libraries that will be loaded
BOOL LibraryHandler::isKnownLibInstruction(ADDRINT address){
	PIN_LockClient();
	IMG curImg = IMG_FindByAddress(address);
	PIN_UnlockClient();
	if (IMG_Valid (curImg) && IMG_Type(curImg) == IMG_TYPE_SHAREDLIB){
		return TRUE;
	}
	return FALSE;

}
