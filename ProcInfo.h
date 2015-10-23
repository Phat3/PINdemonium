#pragma once

#include "pin.H"

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
	RegContext getStartRegContext();
	RegContext getCurrRegContext();
	ADDRINT getFirstINSaddress();
	ADDRINT getPrevIp();
	std::vector<Section> getSections();
	float getInitialEntropy();
	BOOL getPushadFlag();
	BOOL getPopadFlag();
	UINT32 getDumpNumber();

	/* setter */
	void setStartRegContext(CONTEXT * ctx);
	void setCurrRegContext(CONTEXT * ctx);
	void setFirstINSaddress(ADDRINT address);
	void setPrevIp(ADDRINT ip);
	void setInitialEntropy(float Entropy);
	void setPushadFlag(BOOL flag);
	void setPopadFlag(BOOL flag);

	void incrementDumpNumber();
	
	/* debug */
	void PrintStartContext();
	void PrintCurrContext();
	void PrintSections();

	/* helper */
	void ProcInfo::insertSection(Section section);
	string ProcInfo::getSectionNameByIp(ADDRINT ip);
	float GetEntropy();
	
private:
	static ProcInfo* instance;
	ProcInfo::ProcInfo();
	RegContext reg_start_context;
	RegContext reg_curr_context;
	ADDRINT first_instruction;
	ADDRINT prev_ip;
	std::vector<Section> Sections;
	float InitialEntropy;
	//track if we found a pushad followed by a popad
	//this is a common technique to restore the initial register status after the unpacking routine
	BOOL pushad_flag;
	BOOL popad_flag;
	UINT32 dump_number;

};

