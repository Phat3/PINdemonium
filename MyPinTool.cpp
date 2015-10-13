#include <stdio.h>
#include "pin.H"
#include <iostream>
#include <string>
#include "OepFinder.h"

FILE * file;
OepFinder oepf;


// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    fprintf(file, "#eof\n");
    fclose(file);
}


INT32 Usage()
{
    PIN_ERROR("This Pintool prints the hexadecimal of all the instruction executed\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}




// Pin calls this function every time a new instruction is encountered
void Trace(TRACE trace , void *v)
{
	for(BBL bbl= TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
		for( INS ins = BBL_InsHead(bbl); INS_Valid(ins) ; ins =INS_Next(ins)){
			oepf.IsCurrentInOEP(ins);
		}
	}
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{

    file  = fopen("itrace.out", "w");
    
    // Initialize pin
	PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();

	TRACE_AddInstrumentFunction(Trace,0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
