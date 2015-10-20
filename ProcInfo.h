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

	RegContext getStartRegContext();
	RegContext getCurrRegContext();
	ADDRINT getFirstINSaddress();
	ADDRINT getPrevIp();

	void setStartRegContext(RegContext rg);
	void setCurrRegContext(RegContext rg);
	void setFirstINSaddress(ADDRINT address);
	void setPrevIp(ADDRINT ip);
	std::vector<Section> getSections();

	void PrintStartContext();
	void PrintCurrContext();
	void PrintSections();

	void ProcInfo::insertSection(Section section);
	string ProcInfo::getSectionNameByIp(ADDRINT ip);


private:
	static ProcInfo* instance;
	RegContext reg_start_context;
	RegContext reg_curr_context;
	ADDRINT first_instruction;
	ADDRINT prev_ip;
	std::vector<Section> Sections;

};

