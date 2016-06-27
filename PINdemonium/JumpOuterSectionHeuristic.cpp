#include "JumpOuterSectionHeuristic.h"


UINT32 JumpOuterSection::run(INS ins, ADDRINT prev_ip){
	if(prev_ip > 0){
		//get the current IP
		ADDRINT ip = INS_Address(ins);
		//get the name of the current section and teh previos section
		string sec_current = this->getSectionName(ip);
		string sec_prev = this->getSectionName(prev_ip);
		//if they are different then i have detected a jmp outer section
		if(sec_current.compare(sec_prev) && (sec_current.compare("") != 0) && (sec_prev.compare("") != 0)){
			MYWARN("[JMP OUTER SECTION DETECTED!!] FROM : %s	TO : %s", sec_current.c_str(), sec_prev.c_str());
			return OEPFINDER_FOUND_OEP
		}
	}
	return OEPFINDER_HEURISTIC_FAIL;
}

//retrieve the name of the current section
string JumpOuterSection::getSectionName(ADDRINT ip){
	ProcInfo *proc_info = ProcInfo::getInstance();	
	return proc_info->getSectionNameByIp(ip);
}
