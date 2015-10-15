#include <stdio.h>
#include "pin.H"
#include "OepFinder.h"
#include <time.h>
#include  "Debug.h"
#include "Log.h"


namespace W {
	#include <windows.h>
}

OepFinder oepf;
clock_t tStart;

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
	//DEBUG --- inspect the write set at the end of the execution
	WxorXHandler *wxorxHandler = WxorXHandler::getInstance();
	for(std::vector<WriteInterval>::iterator item = wxorxHandler->getWritesSet().begin(); item != wxorxHandler->getWritesSet().end(); ++item) {
		//MYINFO("ADDR BEGIN: %08x         ADDR END:%08x\n", item->getAddrBegin(), item->getAddrEnd());
	}
	MYLOG("WRITE SET SIZE: %d\n", wxorxHandler->getWritesSet().size());
	//DEBUG --- get the execution time
	MYLOG("Total execution Time: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);
	CLOSELOG();
}

//cc
INT32 Usage()
{
	PIN_ERROR("This Pintool unpacks common packers\n" 
			  + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}




// Trace callback Pin calls this function for every trace
void Trace(TRACE trace , void *v)
{
	for(BBL bbl= TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
		for( INS ins = BBL_InsHead(bbl); INS_Valid(ins) ; ins =INS_Next(ins)){

			oepf.IsCurrentInOEP(ins);

		}
	}
}


// Instruction callback Pin calls this function every time a new instruction is encountered
// (Testing if batter than trace iteration)
void Instruction(INS ins,void *v){

	oepf.IsCurrentInOEP(ins);
}




/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{

	tStart = clock();
	
	// Initialize pin
	PIN_InitSymbols();

	if (PIN_Init(argc, argv)) return Usage();

	//TRACE_AddInstrumentFunction(Trace,0);
	INS_AddInstrumentFunction(Instruction,0);

	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	
	// Start the program, never returns
	PIN_StartProgram();
	
	return 0;
}
