#include "ProcInfo.h"
#include "Log.h"
#include "Debug.h"

ProcInfo* ProcInfo::instance = 0;


ProcInfo* ProcInfo::getInstance()
{
	if (instance == 0)
		instance = new ProcInfo;
	return instance;
}


ProcInfo::~ProcInfo(void)
{
}


/* Setter */
void ProcInfo::setStartRegContext(RegContext rg){

	ProcInfo::getInstance()->reg_start_context = rg;

}

void ProcInfo::setCurrRegContext(RegContext rg){

	ProcInfo::getInstance()->reg_curr_context = rg;
}

void ProcInfo::setFirstINSaddress(ADDRINT address){

	ProcInfo::getInstance()->first_instruction  = address;

}

/* Getter */
RegContext ProcInfo::getStartRegContext(){
	return ProcInfo::getInstance()->reg_start_context;
}

RegContext ProcInfo::getCurrRegContext(){
	return ProcInfo::getInstance()->reg_curr_context;
}

ADDRINT ProcInfo::getFirstINSaddress(){
	return ProcInfo::getInstance()->first_instruction;
}

/* Utils + Helper */
void ProcInfo::PrintStartContext(){
	MYLOG("======= START REGISTERS ======= \n");
	MYLOG("EAX: %08x \n" , ProcInfo::getInstance()->getStartRegContext().eax);
	MYLOG("EBX: %08x " , ProcInfo::getInstance()->getStartRegContext().ebx);
	MYLOG("ECX: %08x " , ProcInfo::getInstance()->getStartRegContext().ecx);
	MYLOG("EDX: %08x " , ProcInfo::getInstance()->getStartRegContext().edx);
	MYLOG("ESP: %08x " , ProcInfo::getInstance()->getStartRegContext().esp);
	MYLOG("EBP: %08x " , ProcInfo::getInstance()->getStartRegContext().ebp);
	MYLOG("ESI: %08x " , ProcInfo::getInstance()->getStartRegContext().esi);
	MYLOG("EDI: %08x " , ProcInfo::getInstance()->getStartRegContext().edi);
	MYLOG("============================== \n");
}

void ProcInfo::PrintCurrContext(){

	MYLOG("======= CURRENT REGISTERS ======= \n");
	MYLOG("EAX: %08x \n" , ProcInfo::getInstance()->getCurrRegContext().eax);
	MYLOG("EBX: %08x " , ProcInfo::getInstance()->getCurrRegContext().ebx);
	MYLOG("ECX: %08x " , ProcInfo::getInstance()->getCurrRegContext().ecx);
	MYLOG("EDX: %08x " , ProcInfo::getInstance()->getCurrRegContext().edx);
	MYLOG("ESP: %08x " , ProcInfo::getInstance()->getCurrRegContext().esp);
	MYLOG("EBP: %08x " , ProcInfo::getInstance()->getCurrRegContext().ebp);
	MYLOG("ESI: %08x " , ProcInfo::getInstance()->getCurrRegContext().esi);
	MYLOG("EDI: %08x " , ProcInfo::getInstance()->getCurrRegContext().edi);
	MYLOG("================================= \n");
}


