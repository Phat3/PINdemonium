#include "JumpOuterSection.h"


UINT32 JumpOuterSection::run(INS ins, ADDRINT prev_ip){
	if(prev_ip > 0){
		//get the current IP
		ADDRINT ip = INS_Address(ins);
		//get the name of the current section and teh previos section
		//string sec_current = this->getSectionName(ip);
		//string sec_prev = this->getSectionName(prev_ip);

		string sec_current = "coaa";
		string sec_prev = "ok";
		//if they are different then i have detected a jmp outer section
		if(sec_current.compare(sec_prev)){
			MYLOG("[JMP OUTER SECTION DETECTED!!] FROM : %s	TO : %s", sec_current.c_str(), sec_prev.c_str());
			MYLOG("");
			MYLOG("");
			return OEPFINDER_FOUND_OEP
		}
	}
	return OEPFINDER_FOUND_OEP
}

//retrieve the name of the current section
string JumpOuterSection::getSectionName(ADDRINT ip){
	//POC --- we have to change iut with the ProcInfo object
	IMG img = IMG_FindByAddress(ip); 
	for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) ){
		ADDRINT begin_addr = SEC_Address(sec);
		ADDRINT end_addr = begin_addr + SEC_Size(sec);
		if(ip >= begin_addr && ip < end_addr){
			return SEC_Name(sec);
		}
	}
	return NULL;
}
