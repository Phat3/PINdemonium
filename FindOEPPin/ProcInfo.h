#pragma once

#include "pin.H"
#include "Config.h"
#include "Debug.h"
#include <time.h>
#include <unordered_set>
namespace W{
	#include "windows.h"
}

#define MAX_STACK_SIZE 0x5000    //Used to define the memory range of the stack
#define STACK_BASE_PADDING 0x200 //needed because the stack pointer given by pin is not the highest one
#define TEB_SIZE 0xf28	

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
	ADDRINT getPINVMStart();
	ADDRINT getPINVMEnd();

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
	VOID PrintWhiteListedAddr();

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

	//TEB
	ADDRINT getTebBase();
	VOID initTebAddress();
	BOOL isTebAddress(ADDRINT addr);

	//Stack
	ADDRINT getStackBase();
	VOID setStackBase(ADDRINT addr);
	BOOL isStackAddress(ADDRINT addr);
	
	//Library
	BOOL isAddrInWhiteList(ADDRINT address);
	VOID getWhiteListAddresses();
	BOOL isLibraryInstruction(ADDRINT address);
	BOOL isKnownLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr);
	VOID addLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr);
	VOID addWhitelistAddresses(ADDRINT baseAddr,ADDRINT regionSize);

	//Debug
	void printHeapList();



	
private:
	
	static ProcInfo* instance;
	ProcInfo::ProcInfo();
	ADDRINT first_instruction;
	ADDRINT prev_ip;
	ADDRINT stackBase;								//Stack base address
	ADDRINT tebAddr;                                //Teb Base Address
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

	
	VOID addPinDll(ADDRINT allocationBase,ADDRINT baseAddr,ADDRINT regionSize);
	
};

