#pragma once
#include "pin.H"
#include "WxorXHandler.h"
#include "Report.h"
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
	// 
	
private:
	VOID HandleInjectedMemory(std::vector<WriteInterval>* currentWriteSet,W::DWORD pid);
	string DumpRemoteWriteInterval(WriteInterval* item,W::HANDLE process);
	VOID WriteBufferToFile(unsigned char *buffer,UINT32 size, string path);
	WxorXHandler *wxorxHandler;
	Config *config;
	Report *report;
	static ProcessInjectionModule *instance;
	ProcessInjectionModule(void);
};

