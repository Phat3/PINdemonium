// ScyllaWrapper.cpp: definisce le funzioni esportate per l'applicazione DLL.
//

#pragma once
#include "stdafx.h"
#include "ScyllaWrapper.h"

VOID myFunc(){
	printf("HELLO WANDERsz %d",ScyllaVersionInformationDword());
}


BOOL ScyllaWrapAddSection(const WCHAR * dump_path , const CHAR * sectionName, DWORD sectionSize, UINT32 offset, BYTE * sectionData){
	
	//DebugBreak();
	fflush(stdout);
	return ScyllaAddSection(dump_path , sectionName,sectionSize, offset , sectionData);
}

