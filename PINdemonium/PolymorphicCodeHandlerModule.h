#pragma once
#include "pin.H"

/**
* This class provides a patch for PIN in order to avoid crashes during the instrumentation of polymorphic code
*
* these crashes happen due to the fact that PIN compiles a wrong trace (the one not modified by the code itself) instead of the correct one the one that has been overwritten by the program itself):
*	1. PIN compile the trace and place it in the code caache
*	2. jump to the code cahce and start executing the trace
*	3. an instruction of the trace modify some of the instructions present in the current trace
*	4. PIN continue the execution of the current trace 
*	5. CRASH!!!
*
* This is wrong because the trace has been modified and PIN instead will execute the old instructions which don't have any sense and can cause crashes 
* (executon of a priviled instruction like "out")
*
* Our patch works like this:
*	1. PIN compile the trace and place it in the code caache
*	2. jump to the code cahce and start executing the trace
*	3. in the analysis routine check, if the current instruction is a write, if the target address is inside the current trace and mark this address
*	4. in the analysis routine, if the current instructin has the eip marked, then break the trace and force PIN to build a new one starting from the current eip
*	5. continue the execution fropm the new trace
*/
class PolymorphicCodeHandlerModule
{
public:
	PolymorphicCodeHandlerModule(void);
	~PolymorphicCodeHandlerModule(void);
	VOID inspectTrace(TRACE trace);
	// --- getter and setter --- //
	ADDRINT getTraceHead();
	ADDRINT getTraceTail();
	ADDRINT getFirstWrittenAddressInMesmory();
	VOID setFirstWrittenAddressInMesmory(ADDRINT first_written_address_in_trace);

private: 
	ADDRINT trace_head;
	ADDRINT trace_tail;
	ADDRINT first_written_address_in_trace;
};

