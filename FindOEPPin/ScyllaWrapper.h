#pragma once

namespace W {
#include <windows.h>
};

typedef void (WINAPI * def_myFunc)();
typedef BOOL (WINAPI * def_ScyllaWrapAddSection)(const W::WCHAR * dump_path , const W::CHAR * sectionName, W::DWORD sectionSize, W::BYTE * sectionData)();

class ScyllaWrapper
{

public:
	static ScyllaWrapper* getInstance();
	def_myFunc myFunc;
	def_ScyllaWrapAddSection ScyllaWrapAddSection;

private:
	ScyllaWrapper::ScyllaWrapper();
	static ScyllaWrapper* instance;
	void * hScyllaWrapper;

};

