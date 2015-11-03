#pragma once

#include "pin.H"
#include "Log.h"
#include "Debug.h"
#include <time.h>
#include <unordered_set>


struct RegContext {
 ADDRINT eax;
 ADDRINT ecx;
 ADDRINT edx;
 ADDRINT ebx;
 ADDRINT esp;
 ADDRINT ebp;
 ADDRINT edi;
 ADDRINT esi;
};

//memorize the PE section information
struct Section {
 ADDRINT begin;
 ADDRINT end;
 string name;
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
	BOOL getWXorXFlagBroken();
	std::unordered_set<ADDRINT> getJmpBlacklist();

	/* setter */
	void setFirstINSaddress(ADDRINT address);
	void setPrevIp(ADDRINT ip);
	void setInitialEntropy(float Entropy);
	void setPushadFlag(BOOL flag);
	void setPopadFlag(BOOL flag);
	void setProcName(string name);
	void setStartTimer(clock_t t);
	void setWXorXFlagBroken(BOOL flag);
	
	/* debug */
	void PrintStartContext();
	void PrintCurrContext();
	void PrintSections();

	/* helper */
	void insertSection(Section section);
	string getSectionNameByIp(ADDRINT ip);
	float GetEntropy();
	void insertInJmpBlacklist(ADDRINT ip);
	BOOL isInsideJmpBlacklist(ADDRINT ip);

	
private:
	static ProcInfo* instance;
	ProcInfo::ProcInfo();
	ADDRINT first_instruction;
	ADDRINT prev_ip;
	BOOL w_xor_x_broken_flag;
	std::vector<Section> Sections;
	std::unordered_set<ADDRINT> addr_jmp_blacklist;
	float InitialEntropy;
	//track if we found a pushad followed by a popad
	//this is a common technique to restore the initial register status after the unpacking routine
	BOOL pushad_flag;
	BOOL popad_flag;
	string proc_name;
	clock_t start_timer;
};

