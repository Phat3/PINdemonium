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


	void setStartRegContext(CONTEXT * ctx);
	void setCurrRegContext(CONTEXT * ctx);
	void setFirstINSaddress(ADDRINT address);
	void setPrevIp(ADDRINT ip);
	void setInitialEntropy(float Entropy);
	
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
	RegContext reg_start_context;
	RegContext reg_curr_context;
	ADDRINT first_instruction;
	ADDRINT prev_ip;
	std::vector<Section> Sections;
	float InitialEntropy;

};

