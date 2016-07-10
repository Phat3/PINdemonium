#pragma once
#include "pin.H"
#include "Report.h"
#include "Helper.h"
#include "ReportImportedFunction.h"
namespace W{
	#include <windows.h>
}
#include <string>
#include "Debug.h"
#include <sstream>
#include "Config.h"

//Scylla Wrapper defined constants
#define SCYLLA_ERROR_FILE_FROM_PID -4
#define SCYLLA_ERROR_DUMP -3
#define SCYLLA_ERROR_IAT_NOT_FOUND -2
#define SCYLLA_ERROR_IAT_NOT_FIXED -1
#define SCYLLA_SUCCESS_FIX 0

typedef UINT32 (* def_ScyllaDumpAndFix)(int pid, int oep, W::WCHAR * output_file,W::WCHAR * base_path, W::WCHAR * tmp_dump);
typedef UINT32 (* def_ScyllaWrapAddSection)(const W::WCHAR * dump_path , const W::CHAR * sectionName, W::DWORD sectionSize, UINT32 offset , W::BYTE * sectionData);

class ScyllaWrapperInterface
{

public:
	static ScyllaWrapperInterface* getInstance();
	//Create a process which launch the ScyllaDumper.exe executable to dump the binary and fix the IAT
	UINT32 launchScyllaDumpAndFix(int pid, int curEip, string dumpFileName, string tmpDump, bool call_plugin_flag, string plugin_full_path, string reconstructed_imports_file);
	//interface to the ScyllaWrapper.dll
	def_ScyllaDumpAndFix	ScyllaDumpAndFix;
	def_ScyllaWrapAddSection ScyllaWrapAddSection;
	void loadScyllaLibary();
	void unloadScyllaLibrary();

private:
	Config *config;
	ScyllaWrapperInterface::ScyllaWrapperInterface();
	static ScyllaWrapperInterface* instance;
	void * hScyllaWrapper;
	void addImportFunctionToDumpReport(string reconstructed_imports_file);
};

