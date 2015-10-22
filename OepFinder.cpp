#pragma once
#include "OepFinder.h"
#include "Log.h"
#include "ProcInfo.h"

/* Global variable useful in order to store the registers saved in the callback */
RegContext rg;


OepFinder::OepFinder(void){
	
}

OepFinder::~OepFinder(void){
}


VOID handleWrite(ADDRINT ip, ADDRINT end_addr, UINT32 size)
{		
	FilterHandler *filterHandler = FilterHandler::getInstance();

	//check if the target address belongs to some filtered range		
	if(!filterHandler->isFilteredWrite(end_addr,ip)){	
	//	MYLOG("Examining Write instruction: %x Targetaddr: %x  \n",ip,end_addr);
		WxorXHandler *wxorxHandler=WxorXHandler::getInstance();
		wxorxHandler->writeSetManager(ip, end_addr, size);
	}
}


/*
Save the initial registers inside the struct
You can fine the macro fo the registers at:
https://software.intel.com/sites/landingpage/pintool/docs/49306/Pin/html/group__REG__CPU__IA32.html
*/
VOID getInitialRegisters(CONTEXT * ctx){
	ProcInfo *proc_info = ProcInfo::getInstance();
	proc_info->setStartRegContext(ctx);	
	proc_info->PrintStartContext();
}

//check if the current instruction is a pushad or a popad
//if so then set the proper flags in ProcInfo
void OepFinder::handlePopadAndPushad(INS ins){

	string s = INS_Disassemble(ins);
	if( s.compare("popad ") == 0){
		ProcInfo::getInstance()->setPopadFlag(TRUE);
		return;
	}

	if( s.compare("pushad ") == 0){
		ProcInfo::getInstance()->setPushadFlag(TRUE);
		return;
	}
}

//connect debug
static void ConnectDebugger()
{
    if (PIN_GetDebugStatus() != DEBUG_STATUS_UNCONNECTED){
		 MYINFO("errore  1");
		 return;
	}


    DEBUG_CONNECTION_INFO info;
    if (!PIN_GetDebugConnectionInfo(&info) || info._type != DEBUG_CONNECTION_TYPE_TCP_SERVER){
		  MYINFO("errore  3");
		 return;
	}
    MYINFO("uscitos  1");
	int timeout = 30000;
    if (PIN_WaitForDebuggerToConnect(timeout))
        return;
}

//insert a breakpoint on the current instruction
static VOID DoBreakpoint(const CONTEXT *ctxt, THREADID tid, ADDRINT ip)
{	
    // Construct a string that the debugger will print when it stops.  If a debugger is
    // not connected, no breakpoint is triggered and execution resumes immediately.
    PIN_ApplicationBreakpoint(ctxt, tid, FALSE, "DEBUGGER");
}




UINT32 OepFinder::IsCurrentInOEP(INS ins){
   	
	WxorXHandler *wxorxHandler = WxorXHandler::getInstance();
	FilterHandler *filterHandler = FilterHandler::getInstance();

	ProcInfo *proc_info = ProcInfo::getInstance();

	UINT32 writeItemIndex=-1;
	ADDRINT curEip = INS_Address(ins);
	
	//if it is the first instruction executed from the binary
	if(curEip == proc_info->getFirstINSaddress()){
	   //save the registers 
	   INS_InsertCall(ins,IPOINT_BEFORE, (AFUNPTR)getInitialRegisters , IARG_CONTEXT,IARG_END);
	}

	//check if current instruction is a write
	if(wxorxHandler->isWriteINS(ins)){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleWrite, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	}

	//Tracking violating WxorX instructions
	//Filter instructions inside a known library
	if(filterHandler->isLibraryInstruction(curEip)){
		return OEPFINDER_INS_FILTERED; 
	}

	this->handlePopadAndPushad(ins);

	//If the instruction violate WxorX return the index of the WriteItem in which the EIP is
	//If the instruction doesn't violate WxorX return -1
	writeItemIndex = wxorxHandler->getWxorXindex(curEip);

	if(writeItemIndex != -1 ){

		WriteInterval item = wxorxHandler->getWritesSet().at(writeItemIndex);
		//DEBUG
		//MYLOG("[W xor X BROKEN!] IP : %08x  BEGIN : %08x  END : %08x", curEip, item.getAddrBegin(), item.getAddrEnd());

		ADDRINT prev_ip = proc_info->getPrevIp();

		//call the proper heuristics
		//we have to implement it in a better way!!
		item.setLongJmpFlag(Heuristics::longJmpHeuristic(ins, prev_ip));
		item.setEntropyFlag(Heuristics::entropyHeuristic());
		item.setJmpOuterSectionFlag(Heuristics::jmpOuterSectionHeuristic(ins, prev_ip));
		item.setPushadPopadFlag(Heuristics::pushadPopadHeuristic());
		//wait for scylla
		ConnectDebugger();
		INS_InsertCall(ins,  IPOINT_BEFORE, (AFUNPTR)DoBreakpoint, IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
		

		Log::getInstance()->writeOnReport(curEip, item);

		//delete the WriteInterval just analyzed
		wxorxHandler->deleteWriteItem(writeItemIndex);

	    //update the prevuious IP
		proc_info->setPrevIp(INS_Address(ins));

		return OEPFINDER_HEURISTIC_FAIL;

	}
	//update the previous IP
	proc_info->setPrevIp(INS_Address(ins));
	return OEPFINDER_NOT_WXORX_INST;


}



