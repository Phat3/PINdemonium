#pragma once
#include "pin.H"
#include "WxorXHandler.h"
namespace W{
	#include "windows.h"
}
class ProcessInjectionModule
{
public:
	ProcessInjectionModule(void);

	VOID AddInjectedWrite(ADDRINT start, UINT32 size, W::DWORD  );
private:
	WxorXHandler *wxorxHandler;
};

