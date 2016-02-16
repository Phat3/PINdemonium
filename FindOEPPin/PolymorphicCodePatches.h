#pragma once

#include "pin.H"


/**
* This class provides a patch for PIN in order to avoid crashes during the instrumentation of polymorphic code
*
* these crashes happen due to the fact that PIN compiles a wrong trace (the one not modified by the code itself) instead of the correct one the one that has been overwritten by the program itself):
*	1.PIN compile the trace and place it in the code caache
*	2. jump to the code cahce and start executing the trace
*	3. an instruction of the trace modify some of the instructions present in the current trace
*	4. PIN continue the execution of the current trace 
*	5. CRASH!!!
*
* This is wrong because the trace has been modified and PIN instead will execute the old instructions which don't have any sense and can cause crashes 
* (executon of a priviled instruction like "out"0)
*
*/
class PolymorphicCodePatches
{
public:
	PolymorphicCodePatches(void);
	~PolymorphicCodePatches(void);

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

