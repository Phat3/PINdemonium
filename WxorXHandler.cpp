#include "WxorXHandler.h"


WxorXHandler::WxorXHandler(void)
{
}


WxorXHandler::~WxorXHandler(void)
{
}




BOOL WxorXHandler::isWriteINS(INS ins){
return FALSE;
}

BOOL WxorXHandler::handleWrite(INS ins){

return FALSE;
}

int WxorXHandler::getWxorXindex(INS ins){
	return 1;
}


BOOL WxorXHandler::deleteWriteItem(int writeItemIndex){
	return FALSE;
}
