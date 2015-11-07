#pragma once

#include <Windows.h>
#include <string>

typedef void (WINAPI * def_myFunc)();
typedef UINT32 (WINAPI * def_dump)(int pid, int oep, std::string output_file);

class ScyllaWrapper
{

public:
	static ScyllaWrapper* getInstance();
	def_myFunc myFunc;
	def_dump	dump;

private:
	ScyllaWrapper::ScyllaWrapper();
	static ScyllaWrapper* instance;
	void * hScyllaWrapper;

};

