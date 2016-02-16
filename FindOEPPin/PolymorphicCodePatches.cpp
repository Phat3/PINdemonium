#include "PolymorphicCodePatches.h"


PolymorphicCodePatches::PolymorphicCodePatches(void)
{
	this->trace_head = 0x0;
	this->trace_tail = 0x0;
	this->first_written_address_in_trace = 0x0;
}


PolymorphicCodePatches::~PolymorphicCodePatches(void)
{
}

// -------------------- END PIN ANALYSIS ROUTINE -------------------- //

// Check if we are about to execute an instruction in the trace that modify the trace iteself (polimorfic code)
VOID polimorficCodeHandler(ADDRINT eip, ADDRINT write_addr, void *pcpatchesH){

	PolymorphicCodePatches *pcpatches = (PolymorphicCodePatches *)pcpatchesH;
	// check if the address that the program is about to write is inside our curent trace 
	if(write_addr >= pcpatches->getTraceHead() && write_addr <= pcpatches->getTraceTail()){
		// we want to keep track only the first address written in the trace because it will be the first executed 
		// (NOT TRUE, THE PROGRAM CAN JUMP ON ANOTHER WRITTEN ADRESS AND SKIP THE FIRST ONE -- TO BE MODIFIED --)
		if(write_addr < pcpatches->getFirstWrittenAddressInMesmory() || pcpatches->getFirstWrittenAddressInMesmory() == 0x0){
			 pcpatches->setFirstWrittenAddressInMesmory(write_addr);
		}
	}
}

// check if the address that has to be executed has been written by anoter instruction in the trace (polymorphic code)
// if this is true we have to break the trace and recompile it from the current eip address
VOID checkIfWrittenAddress(ADDRINT eip, CONTEXT * ctxt, UINT32 ins_size, void *pcpatchesH){

	PolymorphicCodePatches *pcpatches = (PolymorphicCodePatches *)pcpatchesH;
	//we have to check if the wriotten address is between the eip and eip + inst_size because 
	// sometime can happen that only part of the original instruction is written
	// ES : push 0x20 -> push 0x30 (only the operand is written)
	if(pcpatches->getFirstWrittenAddressInMesmory() >= eip && pcpatches->getFirstWrittenAddressInMesmory() <= eip + ins_size){
		PIN_SetContextReg(ctxt, REG_EIP, eip);
		//reset the address
		pcpatches->setFirstWrittenAddressInMesmory(0x0);
		// break the terace
		PIN_ExecuteAt(ctxt);
	}
}

// -------------------- END PIN ANALYSIS ROUTINE -------------------- //

VOID PolymorphicCodePatches::inspectTrace(TRACE trace){
	// set the range of address in which the current trace resides
	this->trace_head = TRACE_Address(trace);
	this->trace_tail = trace_head + TRACE_Size(trace);

	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {	
			// for ech instruction we have to check if it has been overwritten by a previous instruction of the current trace (polimiorfic code detection)
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(checkIfWrittenAddress), IARG_INST_PTR, IARG_CONTEXT, IARG_UINT32, INS_Size(ins), IARG_PTR, this,IARG_END);
					
			for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) {
				if(INS_MemoryOperandIsWritten(ins,op)){	
					// for each write operation we have to check if the traget address is inside the current trace (attempt to write polimorfic code)
					INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(polimorficCodeHandler),
					IARG_INST_PTR,
					IARG_MEMORYOP_EA, op,
					IARG_PTR, this,
					IARG_END);
							
				}	
			}					
        }
    }
}


// -------------------- getter and setter -------------------- //

ADDRINT PolymorphicCodePatches::getTraceHead(){
	return this->trace_head;
}

ADDRINT PolymorphicCodePatches::getTraceTail(){
	return this->trace_tail;
}

ADDRINT PolymorphicCodePatches::getFirstWrittenAddressInMesmory(){
	return this->first_written_address_in_trace;
}


VOID PolymorphicCodePatches::setFirstWrittenAddressInMesmory(ADDRINT first_written_address_in_trace){
	this->first_written_address_in_trace = first_written_address_in_trace;
}