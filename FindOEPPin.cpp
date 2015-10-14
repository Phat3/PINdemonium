#include <stdio.h>
#include "pin.H"
#include <iostream>
#include <string>
#include "OepFinder.h"
#include <time.h>
#include  "Debug.h"

FILE * file;
OepFinder oepf;
clock_t tStart;

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
	MYINFO("Total execution Time: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);
	//CLOSELOG();
}


INT32 Usage()
{
    PIN_ERROR("This Pintool unpacks common packers\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}


void imageLoadCallback(IMG img,void *){
	ADDRINT startAddr = IMG_LowAddress(img);
	ADDRINT endAddr = IMG_HighAddress(img);
	
	MYINFO("Image loaded start: %x end: %x\n",startAddr,endAddr);
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

	printf("Strating prototype ins\n");
	tStart = clock();
    
    // Initialize pin
	PIN_InitSymbols();

	

    if (PIN_Init(argc, argv)) return Usage();
	
	//IMG_AddInstrumentFunction(imageLoadCallback,0); 	
//	TRACE_AddInstrumentFunction(Trace,0);
	INS_AddInstrumentFunction(Instruction,0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
