#pragma once
#include "pin.H"
#include "Helper.h"
#include <string.h>
#include "ProcInfo.h"
#include "ScyllaWrapperInterface.h"
#include "OepFinder.h"

namespace W{
	#include "windows.h"
}

class HeapModule
{
public:
	//singleton instance
	static HeapModule* getInstance();
	VOID saveHeapZones(std::map<std::string,HeapZone> hzs, std::map<std::string,std::string> hzs_dumped);
	UINT32 checkHeapWxorX(WriteInterval* item, ADDRINT curEip, int dumpAndFixResult);

private:
	HeapModule(void);
	static HeapModule *instance;
	std::string dumpHZ(HeapZone hz, char * data, std::string hz_md5);
	std::string linkHZ(std::string heap_bin_path);
	void logHZ(std::string heap_link_name, HeapZone hz, std::string hz_md5);

};
