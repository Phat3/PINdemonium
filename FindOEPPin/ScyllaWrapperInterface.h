#pragma once
#include "pin.H"
namespace W{
	#include <windows.h>
}

#include <string>
#include "Debug.h"
#include <sstream>

typedef void (WINAPI * def_myFunc)();
typedef UINT32 (WINAPI * def_ScyllaDumpAndFix)(int pid, int oep, std::string output_file);

class ScyllaWrapperInterface
{

public:
	static ScyllaWrapperInterface* getInstance();
	//Create a process which launch the ScyllaDumper.exe executable to dump the binary and fix the IAT
	BOOL launchScyllaDumpAndFix(string scylla,int pid, int curEip,string dumpFileName);
	//interface to the ScyllaWrapper.dll
	def_myFunc myFunc;
	def_ScyllaDumpAndFix	ScyllaDumpAndFix;

private:
	ScyllaWrapperInterface::ScyllaWrapperInterface();
	static ScyllaWrapperInterface* instance;
	void * hScyllaWrapper;
	
	BOOL existFile (std::string name);

};

