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
	this->hScyllaWrapper = W::LoadLibraryW(L"C:\\pin\\PinUnpackerDependencies\\Scylla\\ScyllaWrapper.dll");
	//get proc address
	if (this->hScyllaWrapper)
	{
		this->myFunc = (def_myFunc)W::GetProcAddress((W::HMODULE)this->hScyllaWrapper, "myFunc");
			if(this->myFunc == NULL){
		printf("myFunc is NULL!!!");
		}
		this->ScyllaWrapAddSection = (def_ScyllaWrapAddSection)W::GetProcAddress((W::HMODULE)this->hScyllaWrapper, "ScyllaWrapAddSection");
		if(this->ScyllaWrapAddSection == NULL){
		printf("ScyllaWrapAddSection is NULL!!!");
		}
	}
}



