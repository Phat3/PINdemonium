#include "ProcessInjectionModule.h"


ProcessInjectionModule::ProcessInjectionModule(void)
{
	wxorxHandler = WxorXHandler::getInstance();

}


VOID ProcessInjectionModule::AddInjectedWrite(ADDRINT start, UINT32 size, W::DWORD pid ){
	wxorxHandler->writeSetManager(start,size,pid);
}