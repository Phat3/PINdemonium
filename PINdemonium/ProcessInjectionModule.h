#pragma once
#include "pin.H"
#include "WxorXHandler.h"
namespace W{
	#include "windows.h"
}
class ProcessInjectionModule
{
public:
	

	//singleton instance
	static ProcessInjectionModule* getInstance();

	VOID AddInjectedWrite(ADDRINT start, UINT32 size, W::DWORD  );
	VOID CheckInjectedExecution(W::DWORD pid );
	VOID DumpInjectedMemory(std::vector<WriteInterval>* currentWriteSet,W::DWORD pid);
private:
	VOID ProcessInjectionModule::WriteBufferToFile(unsigned char *buffer,UINT32 size, string path);
	WxorXHandler *wxorxHandler;
	static ProcessInjectionModule *instance;
	ProcessInjectionModule(void);
	static int number;
};

