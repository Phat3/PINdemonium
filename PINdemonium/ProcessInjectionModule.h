#pragma once
#include "pin.H"
#include "WxorXHandler.h"
#include "Report.h"
#include "Heuristics.h"
#include "Helper.h"
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
	VOID setInsideCreateProcess();
	// 
	
private:
	VOID HandleInjectedMemory(std::vector<WriteInterval>& currentWriteSet,W::DWORD pid);
	string DumpRemoteWriteInterval(WriteInterval* item,W::DWORD pid);
	VOID WriteBufferToFile(unsigned char *buffer,UINT32 size, string path);
	VOID ExecuteHeuristics(string path_to_analyse);
	string getNameFromPid(W::DWORD pid);
	BOOL isInsideCreateProcess();
	WxorXHandler *wxorxHandler;
	Config *config;
	Report *report;
	static ProcessInjectionModule *instance;
	BOOL insideCreateProcess;
	int remoteWriteInsideCreateProcess;
	ProcessInjectionModule(void);
};

