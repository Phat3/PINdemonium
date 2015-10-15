#include "OepFinder.h"
#include "Log.h"


OepFinder::OepFinder(void){
	
}


OepFinder::~OepFinder(void){
}


VOID handleWrite(ADDRINT ip, ADDRINT end_addr, UINT32 size)
{
	WxorXHandler *wxorxHandler=WxorXHandler::getInstance();
	wxorxHandler->writeSetManager(ip, end_addr, size);
}

UINT32 OepFinder::IsCurrentInOEP(INS ins){

	WxorXHandler *wxorxHandler = WxorXHandler::getInstance();

	//W::Sleep(1);
	UINT32 writeItemIndex=-1;
	ADDRINT curEip = INS_Address(ins);
	/*
	if(curEip == 0x00401000){
		MYLOG( "-------------------------------------------------------" );
		MYLOG( "-------------------------------------------------------" );
		MYLOG( "-------------------------------------------------------" );
		MYLOG( "-------------------------------------------------------" );

		std::vector<WriteInterval> v =  wxorxHandler->getWritesSet();

		MYLOG( "IP : %08x" , curEip);
		MYLOG("WRITE SET PRESENTI : %d", v.size());
		for(int i = 0; i < v.size(); i++ ){
			MYLOG( "BEGIN : %08x		END : %08x" ,v.at(i).getAddrBegin(), v.at(i).getAddrEnd() );
		}
	}
	*/
	
	//check if current instruction is a write
	if(wxorxHandler->isWriteINS(ins)){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleWrite, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	}

	//If the instruction violate WxorX return the index of the WriteItem in which the EIP is
	//If the instruction doesn't violate WxorX return -1
	writeItemIndex = wxorxHandler->getWxorXindex(curEip);

	//MYLOG("INDEX : %d", writeItemIndex);
	//if(wxorxHandler->getWxorXindex(ins))
	if(writeItemIndex != -1 ){

		ADDRINT end = wxorxHandler->getWritesSet().at(writeItemIndex).getAddrEnd();
		ADDRINT begin = wxorxHandler->getWritesSet().at(writeItemIndex).getAddrBegin();

		MYLOG("[W xor X BROKEN!] IP : %08x  BEGIN : %08x  END : %08x", curEip, begin, end);
		
		//wxorxHandler->getWritesSet().erase(wxorxHandler->getWritesSet().begin() + writeItemIndex);
		wxorxHandler->deleteWriteItem(writeItemIndex);
		/*
		WriteInterval wi(12,13);


		UINT32 isOEP_Witem = heuristics.callWitemHeuristics(ins,wi);
		UINT32 isOEP_Image = heuristics.callImageHeuristics();
		
			
		if(isOEP_Witem && isOEP_Image){
			return FOUND_OEP;
		}
		*/
		
		return NOT_FOUND_OEP;
	}
	return NOT_WXORX_INST;

}

