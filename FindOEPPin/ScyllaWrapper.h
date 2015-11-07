#pragma once
#include "pin.H"
namespace W{
	#include <windows.h>
}


#include <string>
#include "Debug.h"
#include <sstream>


typedef void (WINAPI * def_myFunc)();

class ScyllaWrapper
{

public:
	static ScyllaWrapper* getInstance();
	//Create a process which launch the ScyllaDumper.exe executable to dump the binary and fix the IAT
	BOOL launchScyllaDumpAndFix(string scylla,int pid, int curEip,string dumpFileName);

	def_myFunc myFunc;

private:
	ScyllaWrapper::ScyllaWrapper();
	static ScyllaWrapper* instance;
	void * hScyllaWrapper;
	
	BOOL existFile (std::string name);

};

