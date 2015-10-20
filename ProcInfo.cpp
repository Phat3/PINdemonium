#include "ProcInfo.h"
#include "Log.h"
#include "Debug.h"

ProcInfo* ProcInfo::instance = 0;

ADDRINT prev_ip = 0;


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

	this->reg_start_context = rg;

}

void ProcInfo::setCurrRegContext(RegContext rg){

	this->reg_curr_context = rg;
}

void ProcInfo::setFirstINSaddress(ADDRINT address){

	this->first_instruction  = address;

}

void ProcInfo::setPrevIp(ADDRINT ip){
	this->prev_ip  = ip;
}

/* Getter */
RegContext ProcInfo::getStartRegContext(){
	return this->reg_start_context;
}

RegContext ProcInfo::getCurrRegContext(){
	return this->reg_curr_context;
}

ADDRINT ProcInfo::getFirstINSaddress(){
	return this->first_instruction;
}

ADDRINT ProcInfo::getPrevIp(){
	return this->prev_ip;
}


/* Utils + Helper */
void ProcInfo::PrintStartContext(){
	MYLOG("======= START REGISTERS ======= \n");
	MYLOG("EAX: %08x \n" , this->getStartRegContext().eax);
	MYLOG("EBX: %08x " , this->getStartRegContext().ebx);
	MYLOG("ECX: %08x " , this->getStartRegContext().ecx);
	MYLOG("EDX: %08x " , this->getStartRegContext().edx);
	MYLOG("ESP: %08x " , this->getStartRegContext().esp);
	MYLOG("EBP: %08x " , this->getStartRegContext().ebp);
	MYLOG("ESI: %08x " , this->getStartRegContext().esi);
	MYLOG("EDI: %08x " , this->getStartRegContext().edi);
	MYLOG("============================== \n");
}

void ProcInfo::PrintCurrContext(){

	MYLOG("======= CURRENT REGISTERS ======= \n");
	MYLOG("EAX: %08x \n" , this->getCurrRegContext().eax);
	MYLOG("EBX: %08x " , this->getCurrRegContext().ebx);
	MYLOG("ECX: %08x " , this->getCurrRegContext().ecx);
	MYLOG("EDX: %08x " , this->getCurrRegContext().edx);
	MYLOG("ESP: %08x " , this->getCurrRegContext().esp);
	MYLOG("EBP: %08x " , this->getCurrRegContext().ebp);
	MYLOG("ESI: %08x " , this->getCurrRegContext().esi);
	MYLOG("EDI: %08x " , this->getCurrRegContext().edi);
	MYLOG("================================= \n");
}


