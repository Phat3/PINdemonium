#pragma once
#include "stdafx.h"
#include <string>

UINT32 ScyllaDumpAndFix(int pid, int oep, WCHAR * output_file,  WCHAR * cur_path, WCHAR * tmp_dump, WCHAR *reconstructed_imports_file);


/* 
   Add a new section to a dumped file 
   
   Args:
   dump_path = path to the dumped file 
   sectionName = name of the new section that you want to create
   sectionSize = size of the section you want to add 
   sectionData = stuff to put in the new section 

   Ret:
   True or False if Scylla sucessfully add the new section  
*/
UINT32 ScyllaWrapAddSection(const WCHAR * dump_path , const CHAR * sectionName, DWORD sectionSize, UINT32 offset, BYTE * sectionData,WCHAR *reconstructed_imports_file);

