#include "JumpOuterSectionHeuristic.h"
#include "ReportJumpOuterSection.h"


UINT32 JumpOuterSection::run(INS ins, ADDRINT prev_ip){
	bool result= false;
	if(prev_ip > 0){
		//get the current IP
		ADDRINT ip = INS_Address(ins);
		//get the name of the current section and teh previos section
		string sec_current = this->getSectionName(ip);
		string sec_prev = this->getSectionName(prev_ip);
		//if they are different then i have detected a jmp outer section
		if(sec_current.compare(sec_prev) && (sec_current.compare("") != 0) && (sec_prev.compare("") != 0)){
			result = true;
			MYWARN("[JMP OUTER SECTION DETECTED!!] FROM : %s	TO : %s", sec_current.c_str(), sec_prev.c_str());
		
		}
		try{
			ReportDump& report_dump = Report::getInstance()->getCurrentDump();
			ReportObject* long_jmp_heur = new ReportJumpOuterSection(result, sec_prev,sec_current);
			report_dump.addHeuristic(long_jmp_heur);
		}
		catch (const std::out_of_range& ){
			MYERRORE("Problem creating ReportJumpOuterSection report");
		}	
	}
	if(result == true){
		return OEPFINDER_FOUND_OEP
	}else{
		return OEPFINDER_HEURISTIC_FAIL
	}
	
	
}

//retrieve the name of the current section
string JumpOuterSection::getSectionName(ADDRINT ip){
	ProcInfo *proc_info = ProcInfo::getInstance();	
	return proc_info->getSectionNameByIp(ip);
}
