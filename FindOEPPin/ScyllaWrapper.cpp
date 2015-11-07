#include "ScyllaWrapper.h"

ScyllaWrapper* ScyllaWrapper::instance = 0;

//singleton
ScyllaWrapper* ScyllaWrapper::getInstance()
{
	if (instance == 0)
		instance = new ScyllaWrapper();
	return instance;
}

ScyllaWrapper::ScyllaWrapper(void)
{
	//init
	this->myFunc = 0;
	this->hScyllaWrapper = 0;
	//load library
	this->hScyllaWrapper = LoadLibraryW(L"C:\\pin\\PinUnpackerDependencies\\Scylla\\ScyllaWrapper.dll");
	//get proc address
	if (this->hScyllaWrapper)
	{
		this->myFunc = (def_myFunc)GetProcAddress((HMODULE)this->hScyllaWrapper, "myFunc");
		this->dump = (def_dump)GetProcAddress((HMODULE)this->hScyllaWrapper, "dump");
	}
}

