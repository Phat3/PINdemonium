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

	void setStartRegContext(RegContext rg);
	void setCurrRegContext(RegContext rg);
	void setFirstINSaddress(ADDRINT address);

	void PrintStartContext();
	void PrintCurrContext();

	void setPrevIp(ADDRINT ip);

	ADDRINT getPrevIp();

private:
	static ProcInfo* instance;
	RegContext reg_start_context;
	RegContext reg_curr_context;
	ADDRINT first_instruction;
	ADDRINT prev_ip;

	//ProcInfo(){};
};

