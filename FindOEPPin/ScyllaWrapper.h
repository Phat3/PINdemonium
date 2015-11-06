#pragma once

#include <Windows.h>

typedef void (WINAPI * def_myFunc)();

class ScyllaWrapper
{

public:
	static ScyllaWrapper* getInstance();
	def_myFunc myFunc;

private:
	ScyllaWrapper::ScyllaWrapper();
	static ScyllaWrapper* instance;
	HMODULE hScyllaWrapper;

};

