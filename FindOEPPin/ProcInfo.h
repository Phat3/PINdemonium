#pragma once

#include "pin.H"
#include "Config.h"
#include "Debug.h"
#include <time.h>
#include <unordered_set>
namespace W{
	#include "windows.h"
}

struct MemoryRange{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
};

//This struct will track the library loaded
//at program startup
struct LibraryItem{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
	string name;
};

//memorize the PE section information
struct Section {
 ADDRINT begin;
 ADDRINT end;
 string name;
};

struct HeapZone {
	ADDRINT begin;
	ADDRINT end;
	UINT32 size;
};

class ProcInfo
{
public:
	//singleton instance
	static ProcInfo* getInstance();
	//distruptor
	~ProcInfo(void);

	/* getter */
	ADDRINT getFirstINSaddress();
	ADDRINT getPrevIp();
	std::vector<Section> getSections();
	float getInitialEntropy();
	BOOL getPushadFlag();
	BOOL getPopadFlag();
	string getProcName();
	clock_t getStartTimer();
	std::unordered_set<ADDRINT> getJmpBlacklist();

	/* setter */
	void setFirstINSaddress(ADDRINT address);
	void setPrevIp(ADDRINT ip);
	void setInitialEntropy(float Entropy);
	void setPushadFlag(BOOL flag);
	void setPopadFlag(BOOL flag);
	void setProcName(string name);
	void setStartTimer(clock_t t);
	
	/* debug */
	void PrintStartContext();
	void PrintCurrContext();
	void PrintSections();

	/* helper */
	void insertSection(Section section);
	string getSectionNameByIp(ADDRINT ip);
	void insertHeapZone(HeapZone heap_zone);
	void deleteHeapZone(UINT32 index);
	UINT32 searchHeapMap(ADDRINT ip);
	HeapZone *getHeapZoneByIndex(UINT32 index);
	float GetEntropy();
	void insertInJmpBlacklist(ADDRINT ip);
	BOOL isInsideJmpBlacklist(ADDRINT ip);
	
	//Library
	BOOL isAddrInWhiteList(ADDRINT address);
	VOID getWhiteListAddresses();
	BOOL isLibraryInstruction(ADDRINT address);
	BOOL isKnownLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr);
	VOID addLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr);

	//Debug
	void printHeapList();



	
private:
	
	static ProcInfo* instance;
	ProcInfo::ProcInfo();
	ADDRINT first_instruction;
	ADDRINT prev_ip;
	std::vector<Section> Sections;
	std::vector<HeapZone> HeapMap;
	std::unordered_set<ADDRINT> addr_jmp_blacklist;
	std::vector<LibraryItem> LibrarySet;			//vector of know library loaded
	std::vector<MemoryRange>  whiteListMemory;
	float InitialEntropy;
	//track if we found a pushad followed by a popad
	//this is a common technique to restore the initial register status after the unpacking routine
	BOOL pushad_flag;
	BOOL popad_flag;
	string full_proc_name;
	string proc_name;
	clock_t start_timer;
	
	//Library Handling Functions
	VOID enumerateMemory(W::HANDLE hProc);

	string libToString(LibraryItem lib);
	VOID showFilteredLibs();
	VOID addWhitelistAddresses(ADDRINT baseAddr,ADDRINT regionSize);
	VOID displayWhiteListedAddr();
	
	VOID addPinDll(ADDRINT allocationBase,ADDRINT baseAddr,ADDRINT regionSize);
	long long FindEx(W::HANDLE hProcess, W::LPVOID MemoryStart, W::DWORD MemorySize, W::LPVOID SearchPattern, W::DWORD PatternSize, W::LPBYTE WildCard);
};

