#pragma once
#include "pin.H"
namespace W{
	#include <windows.h>
}

#include <string>
#include "Debug.h"
#include <sstream>

//Scylla Wrapper defined constants
#define SCYLLA_ERROR_FILE_FROM_PID -4
#define SCYLLA_ERROR_DUMP -3
#define SCYLLA_ERROR_IAT_NOT_FOUND -2
#define SCYLLA_ERROR_IAT_NOT_FIXED -1
#define SCYLLA_SUCCESS_FIX 0

typedef void (WINAPI * def_myFunc)();
typedef UINT32 (* def_ScyllaDumpAndFix)(int pid, int oep, W::WCHAR * output_file);



class ScyllaWrapperInterface
{

public:
	static ScyllaWrapperInterface* getInstance();
	//Create a process which launch the ScyllaDumper.exe executable to dump the binary and fix the IAT
	UINT32 launchScyllaDumpAndFix(string scylla,int pid, int curEip,string dumpFileName);
	//interface to the ScyllaWrapper.dll
	def_myFunc myFunc;
	def_ScyllaDumpAndFix	ScyllaDumpAndFix;

private:
	ScyllaWrapperInterface::ScyllaWrapperInterface();
	static ScyllaWrapperInterface* instance;
	void * hScyllaWrapper;
	
	BOOL existFile (std::string name);

};

