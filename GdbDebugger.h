#pragma once


#include <windows.h>

typedef void *HANDLE;


class GdbDebugger

{
public:
	static GdbDebugger* getInstance();
	void executeCmd(char * cmd);

private:
	static GdbDebugger* instance;
	HANDLE g_hChildStd_IN_Rd;
	HANDLE g_hChildStd_IN_Wr;
	HANDLE g_hChildStd_OUT_Rd;
	HANDLE g_hChildStd_OUT_Wr;
	GdbDebugger(void);
	~GdbDebugger(void);
	void CreateChildProcess();
	void ReadFromPipe(void);
	void WriteToPipe(void);
	void ErrorExit(char * error); 
};

