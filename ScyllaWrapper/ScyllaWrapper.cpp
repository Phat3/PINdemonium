// ScyllaWrapper.cpp: definisce le funzioni esportate per l'applicazione DLL.
//

#pragma once
#include "stdafx.h"
#include "ScyllaWrapper.h"

typedef BOOL (WINAPI * def_myFunc)();

VOID myFunc(){
	printf("HELLO WANDERsz %d",ScyllaVersionInformationDword());
}


BOOL ScyllaWrapAddSection(const WCHAR * dump_path , const CHAR * sectionName, DWORD sectionSize, BYTE * sectionData){
	ScyllaAddSection(dump_path , sectionName,sectionSize,sectionData);
}

