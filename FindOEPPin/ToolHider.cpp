#include "ToolHider.h"
#include <regex>


ToolHider::ToolHider(void)
{
	
}


ToolHider::~ToolHider(void)
{
}


ADDRINT handleRead(ADDRINT eip, ADDRINT read_addr,void *fake_mem_h){
	
	//MYINFO("%0x8 %s Trying to  read %08x : res %d\n",ip,s.c_str(), read_addr,ProcInfo::getInstance()->isAddrInWhiteList(read_addr));
	FakeMemoryHandler fake_mem = *(FakeMemoryHandler *)fake_mem_h;
	//get the new address of the memory operand (same as before if it is inside the whitelist otherwise a NULL poiter)
	ADDRINT fake_addr = fake_mem.getFakeMemory(read_addr, eip);

	if(fake_addr==NULL){

		MYINFO("xxxxxxxxxxxxxx %08x in %s reading %08x",eip, RTN_FindNameByAddress(eip).c_str() , read_addr);
	}

	if(read_addr >= 0x76c0657c && read_addr <= 0x76c06580){
		printf("Readed the field x kernel32!BasepCurrentTopLevelFilter\n");
		fflush(stdout);
	} 

	if (fake_addr != read_addr){
		MYINFO("ip : %08x in %s reading %08x and it has been redirected to : %08x",eip, RTN_FindNameByAddress(eip).c_str() , read_addr, fake_addr);
	}

	return fake_addr;
}

ADDRINT handleWrite(ADDRINT eip, ADDRINT write_addr,void *fakeWriteH){
	
	//MYINFO("%0x8 %s Trying to  read %08x : res %d\n",ip,s.c_str(), read_addr,ProcInfo::getInstance()->isAddrInWhiteList(read_addr));
	FakeWriteHandler fakeWrite = *(FakeWriteHandler *)fakeWriteH;
	//get the new address of the memory operand (same as before if it is inside the whitelist otherwise a NULL poiter)
	ADDRINT fakeAddr = fakeWrite.getFakeWriteAddress(write_addr);

	if(write_addr >= 0x76c0657c && write_addr <= 0x76c06580){
		printf("Written the field x kernel32!BasepCurrentTopLevelFilter\n");
		fflush(stdout);
	} 


	if(fakeAddr != write_addr){
		MYINFO("wwwwwwwwwwwwwwww suspicious write from %08x in %s in %08x redirected to %08x", eip, RTN_FindNameByAddress(write_addr).c_str(), write_addr, fakeAddr);
		MYINFO("Binary writes %08x\n" , *(unsigned int *)(fakeAddr));
	}
	
	return fakeAddr;
}



//get the first scratch register available
//we build a vector in order to deal with multiple read operand
static REG GetScratchReg(UINT32 index)
{
    static std::vector<REG> regs;

    while (index >= regs.size())
    {
		//get thefirst clean register
        REG reg = PIN_ClaimToolRegister();
        regs.push_back(reg);
    }

    return regs[index];
}


unsigned int first_ebx;



VOID MyPrintRegEbx1(CONTEXT *ctxt){
		
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("This stub (AA) is writing to %08x , number of bytes written 524 - 0x20c\n\n" , ebx_value);

		return;
}

VOID MyPrintRegEdx1(CONTEXT *ctxt){
		
		unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);

		MYINFO("Inside stub (AB) - first pattern match , the edx register value is %08x\n" , edx_value);

		return;
}


VOID MyPrintRegEcx1(CONTEXT *ctxt){
		
		unsigned int ecx_value = PIN_GetContextReg(ctxt, REG_ECX);

		MYINFO("Inside stub (AB) - second pattern match , the ecx register value is %08x\n" , ecx_value);

		return;
}

VOID MyPrintRegEcx2(CONTEXT *ctxt){
		
		unsigned int ecx_value = PIN_GetContextReg(ctxt, REG_ECX);

		MYINFO("Inside stub (AB) - third pattern match , the ecx register value is %08x\n" , ecx_value);

		return;
}

VOID MyPrintRegEcx3(CONTEXT *ctxt){
		
		unsigned int ecx_value = PIN_GetContextReg(ctxt, REG_ECX);

		MYINFO("Inside stub (AB) - 4th pattern match , the ecx register value is %08x\n" , ecx_value);

		return;
}

VOID MyPrintRegEcx4(CONTEXT *ctxt){
		
		unsigned int ecx_value = PIN_GetContextReg(ctxt, REG_ECX);

		MYINFO("Inside stub (AB) - 5th pattern match , the ecx register value is %08x\n" , ecx_value);

		return;
}

VOID MyPrintRegEcx5(CONTEXT *ctxt){
		
		unsigned int ecx_value = PIN_GetContextReg(ctxt, REG_ECX);
		unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);

		MYINFO("Inside stub (AB) - 6th pattern match , moving stuff from ecx into [eax]\n");
		MYINFO("the ecx register value is %08x\n" , ecx_value);
		MYINFO("the [eax] value is %08x\n" , *(unsigned int *)eax_value);

		return;
}

VOID MyPrintRegEdx(CONTEXT *ctxt){
		
		unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);
		MYINFO("This stub (AC) is writing to %08x, number of bytes written 1024 - 0x400\n", edx_value);

		return;
}

VOID MyPrintRegEdx2(CONTEXT *ctxt){
		
		unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);
		MYINFO("Inside stub (AD) - 1st pattern match, value of edx is %08x\n", edx_value);

		return;
}

VOID MyPrintRegEax2(CONTEXT *ctxt){
		
		unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
		MYINFO("Inside stub (AD) - 2nd pattern match, value of eax is %08x\n", eax_value);

		return;
}


VOID MyPrintRegAD3(CONTEXT *ctxt){
		
		unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);
		unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);

		MYINFO("Inside stub (AD) - 3rd pattern match, value of edx is %08x\n", edx_value);
		MYINFO("Calling the function at %08x with the following parameters: eax: %08x , 0x844fbd37 , 0x0" , *(unsigned int *)edx_value+0x2b4 , eax_value);
		return;
}

VOID MyPrintRegAD4(CONTEXT *ctxt){
		
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
		unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
		unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);
		unsigned int edi_value = PIN_GetContextReg(ctxt, REG_EDI);

		MYINFO("Inside stub (AD) - 4th pattern match, value of eax: %08x | ebx: %08x | esi: %08x | edi %08x \n", eax_value , ebx_value , esi_value , edi_value );

		return;
}

VOID MyPrintRegAD5(CONTEXT *ctxt){
		
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
		unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);

		MYINFO("Inside stub (AD) - 5th pattern match, value of  ebx: %08x | esi: %08x \n", ebx_value , esi_value );

		return;
}

VOID MyPrintRegAD6(CONTEXT *ctxt){
			
	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
		unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);

		MYINFO("Inside stub (AD) - 6th pattern match, value of  ebx: %08x | esi: %08x \n", ebx_value , esi_value );

		return;
}

VOID MyPrintRegAD7(CONTEXT *ctxt){
			
	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("Inside stub (AD) - 7th pattern match-BEFORE , value of  ebx: %08x \n", ebx_value );

		return;
}

VOID MyPrintRegAD7A(CONTEXT *ctxt){
			
	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);

		MYINFO("Inside stub (AD) - 7th pattern match-AFTER , value of  eax: %08x \n", eax_value );

		return;
}

VOID MyPrintRegAD8(CONTEXT *ctxt){
			
	    unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("Inside stub (AD) - 8th pattern match , value of  edx: %08x \n", edx_value );
		MYINFO("Calling function at %08x\n" , *(unsigned int *) ebx_value+0x2b4);

		return;
}

VOID MyPrintRegAD9(CONTEXT *ctxt){
			
	    unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);
		unsigned int ecx_value = PIN_GetContextReg(ctxt, REG_ECX);

		MYINFO("Inside stub (AD) - 9th pattern match , value of  edx: %08x | ecx: %08x \n", edx_value , ecx_value);

		return;
}

VOID MyPrintRegAD10(CONTEXT *ctxt){
			
	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("Inside stub (AD) - 10th pattern match , value of ebx is %08x\n" , ebx_value);
		MYINFO("Calling function at %08x\n" , *(unsigned int *)ebx_value+0x154);

		return;
}

VOID MyPrintRegAD11(CONTEXT *ctxt){
			
	    unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);

		MYINFO("Inside stub (AD) - 11th pattern match , value of edx is %08x\n" , edx_value);

		return;
}

VOID MyPrintRegAD12(CONTEXT *ctxt){
			
	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("Inside stub (AD) - 12th pattern match , value of ebx is %08x\n" , ebx_value);
		MYINFO("Calling function at %08x\n" , *(unsigned int *)ebx_value+0x2b4);


		return;
}

VOID MyPrintRegAF1(CONTEXT *ctxt){
			
	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);


	    MYINFO("This stub (AF) is writing to %08x , number of bytes written 192 - 0xc0\n\n" , eax_value);


		return;
}

VOID MyPrintRegAG1(CONTEXT *ctxt){
			
	    unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("Inside stub (AG) - 1st pattern match , value of ebx is %08x , esi: %08x\n" , ebx_value , esi_value);
		MYINFO("Calling to a function at %08x\n" , *(unsigned int *)ebx_value+0x2b4);



		return;
}


VOID MyPrintRegAG2(CONTEXT *ctxt){

		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
		unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);

		MYINFO("Inside stub (AG) - 2nd pattern match , value of eax is %08x" , eax_value);
		MYINFO("Calling to a function at %08x\n" , *(unsigned int *)ebx_value+0x74);

		return;
}

VOID MyPrintRegAG3(CONTEXT *ctxt){

	    unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
		unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
		unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);

		MYINFO("Inside stub (AG) - 3rd pattern match , value of ebx is %08x , esi: %08x , eax: %08x , edx : %08x\n" , ebx_value , esi_value, eax_value , edx_value);
		MYINFO("Calling to a function at %08x\n" , *(unsigned int *)ebx_value+0x2b4);

		return;
}

VOID MyPrintRegAH1(CONTEXT *ctxt){

	    unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);

		MYINFO("This stub (AH) is writing to %08x , number of bytes written 236 - 0xec\n\n" , esi_value);

		return;
}

VOID MyPrintRegAI1(CONTEXT *ctxt){

	    unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("Inside stub (AI) - 1st pattern match , edx is %08x , ebx: %08x\n " , edx_value , ebx_value);
		MYINFO("Calling to a function at %08x\n" , *(unsigned int *)ebx_value+0x2b4);


		return;
}

VOID MyPrintRegAI2(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("Inside stub (AI) - 2nd pattern match , eax is %08x , ebx: %08x\n " , eax_value , ebx_value);
		MYINFO("Calling to a function at %08x\n" , *(unsigned int *)ebx_value+0x74);


		return;
}

VOID MyPrintRegAI3(CONTEXT *ctxt){

	    unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);

		MYINFO("Inside stub (AI) - 3rd pattern match , esi is %08x\n " , esi_value);

		return;
}

VOID MyPrintRegAI4(CONTEXT *ctxt){

	    unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);
	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("Inside stub (AI) - 4th pattern match , edx is %08x , eax: %08x , ebx: %08x\n " , edx_value, eax_value , ebx_value);
		MYINFO("Calling to a function at %08x\n" , *(unsigned int *)ebx_value+0x2b4);

		return;
}

VOID MyPrintRegAI5(CONTEXT *ctxt){

	    unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);
		
		MYINFO("Probably attemp to overwriting the ntdll\n");
		MYINFO("Inside stub (AI) - 5th pattern match , esi is %08x\n " , esi_value);

		return;
}


VOID MyPrintRegAI6(CONTEXT *ctxt){

	    unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);
		unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
		
		MYINFO("Inside stub (AI) - 6th pattern match , esi is %08x , edx: %08x , ebx: %08x \n " , esi_value , edx_value , ebx_value);
		MYINFO("Stuff at [edx] is %08x\n" , *(unsigned int *)edx_value);
		MYINFO("Calling to a function at %08x\n" , *(unsigned int *)ebx_value+0x2b4);

		return;
}

VOID MyPrintRegAL1(CONTEXT *ctxt){

		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
		MYINFO("This stub (AL) is writing to %08x, number of bytes written 596 - 0x254\n", ebx_value);

		return;
}

VOID MyPrintRegAM1(CONTEXT *ctxt){

	    unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);
		unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("Inside stub (AM) - 1st pattern match , esi is %08x , edx: %08x , ebx: %08x \n " , esi_value , edx_value , ebx_value);

		return;
}

VOID MyPrintRegAM2(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);

		MYINFO("Inside stub (AM) - 2nd pattern match , eax is %08x\n " , eax_value);

		return;
}

VOID MyPrintRegAM3(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);

		MYINFO("Pattern match of the teb access\n");
		MYINFO("Inside stub (AM) - 3rd pattern match , eax is %08x\n " , eax_value);

		return;
}

VOID MyPrintRegAM4(CONTEXT *ctxt){

	    unsigned int esp_value = PIN_GetContextReg(ctxt, REG_ESP);

		MYINFO("The value of esp will be putted inside fs:[eax]\n");
		MYINFO("Inside stub (AM) - 4th pattern match , esp is %08x\n " , esp_value);
		MYINFO("Address of the installed handler is %08x\n" , *(unsigned int *)(esp_value + 4));

		return;
}

VOID MyPrintRegAM5(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);

		MYINFO("This is the value of eax before the cpuid\n");
		MYINFO("Inside stub (AM) - 5th pattern match BEFORE , eax is %08x\n " , eax_value);

		return;
}

VOID MyPrintRegAM5A(CONTEXT *ctxt){

	    unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);

		MYINFO("This is the return value of cpuid\n");
		MYINFO("Inside stub (AM) - 5th pattern match AFTER , edx is %08x\n " , edx_value);
		
		return;
}

VOID MyPrintRegAM6(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
	    unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);

		MYINFO("Inside stub (AM) - 6th pattern match , eax is %08x , esi: %08x\n " , eax_value , esi_value);
		MYINFO("Comparing eax with %08x\n" , *(unsigned int *)esi_value+0x64);

		return;
}

VOID MyPrintRegAM7(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
		MYINFO("Inside stub (AM) - 7th pattern match , eax is %08x\n " , eax_value);
		
		return;
}

VOID MyPrintRegAN1(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
		MYINFO("This stub (AN) is writing to %08x , number of bytes written 268 - 0x10c\n\n" , eax_value);
		
		return;
}

VOID MyPrintRegAO1(CONTEXT *ctxt){

	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
	    unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);
	    unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);

		MYINFO("Inside stub (AO) - 1st pattern match , ebx is %08x , edx: %08x , esi: %08x \n " , ebx_value , edx_value , esi_value);

		return;
}

VOID MyPrintRegAO2(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);

		MYINFO("Inside stub (AO) - 2nd pattern match , eax is %08x\n " , eax_value);

		return;
}

VOID MyPrintRegAO3(CONTEXT *ctxt){

	    unsigned int esp_value = PIN_GetContextReg(ctxt, REG_ESP);

		MYINFO("Inside stub (AO) - 3rd pattern match , esp is %08x\n " , esp_value);

		return;
}

VOID MyPrintRegAO4(CONTEXT *ctxt){

	    unsigned int esp_value = PIN_GetContextReg(ctxt, REG_ESP);
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);


		MYINFO("Inside stub (AO) - 4th pattern match , esp is %08x , ebx: %08x\n " , esp_value , ebx_value);
		MYINFO("Calling to a function at %08x\n" , *(unsigned int *)ebx_value+0x2b4);
		
		return;
}

VOID MyPrintRegAO5(CONTEXT *ctxt){

	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
		unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);


		MYINFO("Inside stub (AO) - 5th pattern match , ebx is %08x , eax: %08x\n " , ebx_value , eax_value);
		MYINFO("Comparing eax with value at [ebx+0x64]: %08x\n" , *(unsigned int *)ebx_value+0x64);
		
		return;
}

VOID MyPrintRegAO6(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);

		MYINFO("Inside stub (AO) - 6th pattern match , eax is %08x\n " , eax_value);
		
		return;
}

VOID MyPrintRegAO7(CONTEXT *ctxt){

	    unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);

		MYINFO("Inside stub (AO) - 7th pattern match , esi is %08x\n " , esi_value);
		MYINFO("Comparing 0x0 with memory at [esi-0x6]: %08x\n" , *(unsigned int *)esi_value-0x6);
		return;
}

VOID MyPrintRegAP1(CONTEXT *ctxt){

	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
		MYINFO("This stub (AP) is writing to %08x, number of bytes written 1968 - 0x7b0\n", ebx_value);

		
		return;
}

VOID MyPrintRegAQ1(CONTEXT *ctxt){

	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
	    unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);

		MYINFO("Inside stub (AQ) - 1st pattern match , ebx is %08x , edx: %08x\n " , ebx_value , edx_value);

		
		return;
}

VOID MyPrintRegAQ2(CONTEXT *ctxt){

	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("Inside stub (AQ) - 2n pattern match , ebx is %08x\n " , ebx_value);
		MYINFO("Calling to a function at %08x\n" , *(unsigned int *)ebx_value+0x2b4);

		return;
}

VOID MyPrintRegAQ3(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
	    unsigned int ebp_value = PIN_GetContextReg(ctxt, REG_EBP);

		MYINFO("Inside stub (AQ) - 3rd pattern match , eax is %08x , ebp-0x4 is: %08x\n " , eax_value , ebp_value-0x4);
		MYINFO("Moving eax_value at %08x\n" , *(unsigned int *)ebp_value-0x4);

		return;
}

VOID MyPrintRegAQ4(CONTEXT *ctxt){

	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("Inside stub (AQ) - 4th pattern match , ebx is %08x\n " , ebx_value);
		MYINFO("Testing [ebx+0x2e8]: %08x with 0x4\n" , *(unsigned int *)ebx_value+0x2e8);

		return;
}

VOID MyPrintRegAQ5(CONTEXT *ctxt){

	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
	    unsigned int ebp_value = PIN_GetContextReg(ctxt, REG_EBP);

		MYINFO("Inside stub (AQ) - 5th pattern match , ebx is %08x , ebp: %08x\n " , ebx_value , ebp_value);
		MYINFO("Parameter pushed [ebp-0x4]: %08x\n" , *(unsigned int *)ebp_value-0x4);
		MYINFO("Calling function at %08x\n" , *(unsigned int *)ebx_value+0x74);

		return;
}

VOID MyPrintRegAQ6(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);

		MYINFO("Probably this is the anti-PIN check\n");
		MYINFO("Inside stub (AQ) - 6th pattern match , eax is %08x \n " , eax_value);
		MYINFO("Comparing with 0xe9 the memory at [eax]: %08x\n" , *(unsigned int *)eax_value);
		
		PIN_SetContextReg(ctxt, REG_EAX, 0x00402e00);

		return;
}

VOID MyPrintRegAQ7(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);

		MYINFO("Probably this is the anti-PIN check\n");
		MYINFO("Inside stub (AQ) - 7th pattern match , eax is %08x \n " , eax_value);
		MYINFO("Comparing with 0xeb the memory at [eax]: %08x\n" , *(unsigned int *)eax_value);
		
		PIN_SetContextReg(ctxt, REG_EAX, 0x00402e00); //TEMP

		return;
}

VOID MyPrintRegAQ8(CONTEXT *ctxt){

	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
	    unsigned int ebp_value = PIN_GetContextReg(ctxt, REG_EBP);

		MYINFO("Inside stub (AQ) - 8th pattern match , ebx is %08x , ebp: %08x \n " , ebx_value , ebp_value);
		MYINFO("Pushing the value [ebp-0x4]: %08x\n", *(unsigned int *)ebp_value-0x4);
		MYINFO("Calling the function at %08x\n", *(unsigned int *)ebx_value+0x74);

		return;
}

VOID MyPrintRegAQ9(CONTEXT *ctxt){

	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);

		MYINFO("Inside stub (AQ) - 9th pattern match , ebx is %08x\n " , ebx_value);
		MYINFO("Calling the function at %08x\n", *(unsigned int *)ebx_value+0x2b4);

		return;
}

VOID MyPrintRegAQ10(CONTEXT *ctxt){

	    unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
	    unsigned int ecx_value = PIN_GetContextReg(ctxt, REG_ECX);
	    unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);

		MYINFO("Inside stub (AQ) - 10th pattern match , eax is %08x , ecx: %08x , edx: %08x\n " , eax_value , ecx_value , edx_value);

		return;
}

VOID MyPrintRegAQ11(CONTEXT *ctxt){

	    unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
	    unsigned int ebp_value = PIN_GetContextReg(ctxt, REG_EBP);

		MYINFO("Inside stub (AQ) - 11th pattern match , ebx is %08x , ebp: %08x\n" , ebx_value , ebp_value);
		MYINFO("Pushing parameter [ebp-0x8]: %08x\n" , *(unsigned int *)ebp_value-0x8);
		MYINFO("Calling function at %08x\n" , *(unsigned int *)ebx_value+0x2ec);

		return;
}

VOID MyPrintRegAQ12(CONTEXT *ctxt){

	    unsigned int ebp_value = PIN_GetContextReg(ctxt, REG_EBP);

		MYINFO("Inside stub (AQ) - 12th pattern match , ebp is %08x\n" , ebp_value);
		MYINFO("Comparing [ebp-0x14]: %08x with 0x4\n", *(unsigned int *)ebp_value-0x14);
		MYINFO("Comparing [ebp-0xc]: %08x with 0x0\n", *(unsigned int *)ebp_value-0xc);

		return;
}

VOID MyPrintRegAQ13(CONTEXT *ctxt){

	    unsigned int ebp_value = PIN_GetContextReg(ctxt, REG_EBP);

		MYINFO("Inside stub (AQ) - 13th pattern match , ebp is %08x\n" , ebp_value);
		MYINFO("Moving into [ebp-0x18]: %08x the value 0x0\n", *(unsigned int *)ebp_value-0x18);

		return;
}

VOID MyPrintRegAQ14(CONTEXT *ctxt){

	    unsigned int ebp_value = PIN_GetContextReg(ctxt, REG_EBP);
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
		unsigned int ecx_value = PIN_GetContextReg(ctxt, REG_ECX);
		unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);

		MYINFO("Inside stub (AQ) - 14th/15th pattern match , ebp is %08x , ebx: %08x , ecx: %08x , edx: %08x\n" , ebp_value , ebx_value , ecx_value ,edx_value);
		MYINFO("Pushing parameter [ebp-0x10]: %08x , [ebp-0x8]: %08x\n", *(unsigned int *)ebp_value-0x10,*(unsigned int *)ebp_value-0x8);
		MYINFO("Calling function at %08x\n" , *(unsigned int *)ebx_value+0x2ec);

		return;
}

VOID MyPrintRegAQ16(CONTEXT *ctxt){

	    unsigned int ebp_value = PIN_GetContextReg(ctxt, REG_EBP);
		unsigned int ebx_value = PIN_GetContextReg(ctxt, REG_EBX);
		unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);

		MYINFO("Inside stub (AQ) - 16th pattern match , ebp is %08x , ebx: %08x , edx: %08x\n" , ebp_value , ebx_value ,edx_value);
		MYINFO("Comparing [ebp-0x14]: %08x with 0x4\n" , *(unsigned int *)ebp_value-0x14);
		MYINFO("Comparing [ebp-0x20]: %08x with 0x0\n" , *(unsigned int *)ebp_value-0x20);
		MYINFO("Adding to [ebx+0x110]: %08x the constant 0xc\n" , *(unsigned int *)ebx_value+0x110);

		return;
}


VOID MyCallStrange(CONTEXT *ctxt){
	
	unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
	unsigned int esi_value = PIN_GetContextReg(ctxt, REG_ESI);


	MYINFO("eax_value is %08x\n" , eax_value);
	MYINFO("esi value is %08x\n", esi_value);

	MYINFO("Trying to get the strings if this is a create file\n");

	//MYINFO("%s %s\n" , eax_value , esi_value);


}

VOID PrintFs(CONTEXT *ctxt){

	unsigned int flags = PIN_GetContextReg(ctxt,REG_EFLAGS);

	MYINFO("******FLAGS BEFORE are %08x\n" , flags);

	MYINFO("******SETTING THE TRAP FLAG\n");

	//flags = flags | 0x100;

	MYINFO("******FLAGS AFTER are %08x\n" , flags);

	unsigned int efs_value = PIN_GetContextReg(ctxt , REG_SEG_FS_BASE);
	MYINFO("efs_value is %08x , address of next SEH is %08x, current SEH is %08x\n" , efs_value , *(unsigned int *)efs_value , *(unsigned int *)(efs_value + 4));

	unsigned int next_record_address = *(unsigned int *)efs_value;

	
	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" , *(unsigned int *)next_record_address ,   *(unsigned int *)(next_record_address+4));
	
	/*
	next_record_address = *(unsigned int *)next_record_address;
	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" , *(unsigned int *)next_record_address ,   *(unsigned int *)(next_record_address+4));

	
	
	next_record_address = *(unsigned int *)next_record_address;
	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" , *(unsigned int *)next_record_address ,   *(unsigned int *)(next_record_address+4));
	/*
	next_record_address = *(unsigned int *)next_record_address;
	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" , *(unsigned int *)next_record_address ,   *(unsigned int *)(next_record_address+4));
	*/

	PIN_SetContextReg(ctxt,REG_EIP,*(unsigned int *)(next_record_address+4));
	PIN_ExecuteAt(ctxt);
	
}

VOID MyJumpException(CONTEXT *ctxt){

	unsigned int efs_value = PIN_GetContextReg(ctxt , REG_SEG_FS_BASE);
	MYINFO("efs_value is %08x , address of next SEH is %08x, current SEH is %08x\n" , efs_value , *(unsigned int *)efs_value , *(unsigned int *)(efs_value + 4));


	unsigned int next_record_address = *(unsigned int *)efs_value;

	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" ,  *(unsigned int *)efs_value ,   *(unsigned int *)(efs_value + 4));

	/*
	next_record_address = *(unsigned int *)next_record_address;

	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" , *(unsigned int *)next_record_address ,   *(unsigned int *)(next_record_address+4));
	/*
	next_record_address = *(unsigned int *)next_record_address;
	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" , *(unsigned int *)next_record_address ,   *(unsigned int *)(next_record_address+4));

	next_record_address = *(unsigned int *)next_record_address;
	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" , *(unsigned int *)next_record_address ,   *(unsigned int *)(next_record_address+4));

	next_record_address = *(unsigned int *)next_record_address;
	MYINFO("----@#NEXT SEH RECORD#@\n---");
	MYINFO("Next SEH %08x , SEH value %08x\n" , *(unsigned int *)next_record_address ,   *(unsigned int *)(next_record_address+4));
	*/
	//PIN_SetContextReg(ctxt,REG_EIP,*(unsigned int *)(efs_value + 4));
	//PIN_ExecuteAt(ctxt);
	
}


VOID MyPrintRegMM1(CONTEXT *ctxt){

		unsigned int eax_value = PIN_GetContextReg(ctxt, REG_EAX);
		unsigned int esp_value = PIN_GetContextReg(ctxt, REG_ESP);
		unsigned int ecx_value = PIN_GetContextReg(ctxt, REG_ECX);

		MYINFO("Inside Main module, eax is %08x , esp: %08x , ecx: %08x\n" , eax_value , esp_value, ecx_value);

		return;
}

VOID MyPrintRegMM2(CONTEXT *ctxt){


	//[edx+0xb8], 0x96
		unsigned int edx_value = PIN_GetContextReg(ctxt, REG_EDX);
	
		MYINFO("Inside Main module, edx is %08x\n" , edx_value);
		MYINFO("Accessing [%08x] -> %08x\n" , edx_value+0xb8, *(unsigned int *)edx_value+0xb8);

		return;
}





void ToolHider::avoidEvasion(INS ins){

   ADDRINT curEip = INS_Address(ins);
   ProcInfo *pInfo = ProcInfo::getInstance();
   Config *config = Config::getInstance();
   FilterHandler *filterHandler = FilterHandler::getInstance();

	//Filter instructions inside a known library (only graphic dll)
    //  pInfo->isKnownLibraryInstruction(curEip) 
   if(filterHandler->isFilteredLibraryInstruction(curEip)){
		//MYINFO("That's a GDI\n\n");
		//MYINFO("Name of RTN is %s\n" , RTN_FindNameByAddress(curEip).c_str());
	    //MYINFO("Skipping filtered library code\n");
		return;
	}




	if(pInfo->searchHeapMap(curEip)!=-1){
	   //printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@inside the heap code\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");


	   //-------------- STUB AA---------------------
	   if(strcmp( (INS_Disassemble(ins).c_str() ),"mov byte ptr [ebx], 0x36") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);


		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegEbx1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
     }

	//---------------------------------------------

	//----------------- STUB AB -------------------
	  if(strcmp( (INS_Disassemble(ins).c_str() ),"mov eax, dword ptr [edx-0x9]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegEdx1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
     }  

	if(strcmp( (INS_Disassemble(ins).c_str() ),"mov dword ptr [eax+0xe4], ecx") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegEcx1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
		
     } 

	if(strcmp( (INS_Disassemble(ins).c_str() ),"mov dword ptr [eax+0x44], ecx") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegEcx2, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
     } 

    if(strcmp( (INS_Disassemble(ins).c_str() ),"mov dword ptr [eax+0x274], ecx") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegEcx3, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
     } 

    if(strcmp( (INS_Disassemble(ins).c_str() ),"mov dword ptr [eax+0x100], ecx") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegEcx4, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
     }

    if(strcmp( (INS_Disassemble(ins).c_str() ),"mov dword ptr [eax], ecx") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegEcx5, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
     } 

	//------------------------------------------------

	//-------------- STUB AC -------------------------

	if(strcmp( (INS_Disassemble(ins).c_str() ),"mov byte ptr [edx], 0xb8") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegEdx, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
     } 

	//------------------------------------------------


	//--------------- STUB AD ------------------------

	if(strcmp( (INS_Disassemble(ins).c_str() ),"mov edx, dword ptr [ebx-0xd]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegEdx2, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
     } 

	if(strcmp( (INS_Disassemble(ins).c_str() ),"mov dword ptr [edx+0x29c], ecx") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegEax2, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
     } 
	
	if(strcmp( (INS_Disassemble(ins).c_str() ),"call dword ptr [edx+0x2b4]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAD3, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
     } 
	
	if(strcmp( (INS_Disassemble(ins).c_str() ),"lea eax, ptr [ebx-0x9]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAD4, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
		}
     } 
	
	if(strcmp( (INS_Disassemble(ins).c_str() ),"mov ebx, dword ptr [esi-0x214]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAD5, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
		}
     } 


	if(strcmp( (INS_Disassemble(ins).c_str() ),"lea edx, ptr [esi+0x1d8]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAD6, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
		}
     } 

	if(strcmp( (INS_Disassemble(ins).c_str() ),"mov eax, dword ptr [esi+0x1d4]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAD7, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAD7A, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
		}
     } 

	if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0x2f01ae99") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAD8, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);

     } 

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov ecx, dword ptr [ebp+0xc]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAD9, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
		}
     } 
	
if(strcmp( (INS_Disassemble(ins).c_str() ),"call dword ptr [ebx+0x154]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAD10, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
     } 

if(strcmp( (INS_Disassemble(ins).c_str() ),"lea edx, ptr [esi+0x1d8]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

	if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAD11, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END);
		}     
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"call dword ptr [ebx+0x2b4]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAD12, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}


//------------------------------------------

//-------------- STUB AF -------------------
if(strcmp( (INS_Disassemble(ins).c_str() ),"mov byte ptr [eax], 0x38") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAF1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}


//------------- STUB AG -------------------
if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0x4552d021") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAG1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		}
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0x466f2056") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAG2, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}


if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0x19e65db6") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAG3, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}


//-----------------------------------------

//------------ STUB AH --------------------

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov eax, 0xec") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAH1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

//----------------------------------------

//----------- STUB AI --------------------

if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0x4552d021") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAI1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}


if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0xec63cd77") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAI2, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"lea edx, ptr [ebp-0x4]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAI3, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0x10066f2f") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAI4, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov byte ptr [esi], 0xc3") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAI5, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0x10066f2f") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAI6, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

//-------------------------------------

//---------- STUB AL ------------------

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov esi, 0x254") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAL1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

//------------------------------------

//------------- STUB AM -----------------

if(strcmp( (INS_Disassemble(ins).c_str() ),"lea edx, ptr [ebx+0x13e]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAM1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		}
}


if(strcmp( (INS_Disassemble(ins).c_str() ),"mov eax, dword ptr [esi+0x64]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAM2, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		}
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"push dword ptr fs:[eax]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAM3, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		}
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov dword ptr fs:[eax], esp") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAM4, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		}
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"cpuid ") == 0){

	INS_Delete(ins);
	
		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAM5, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAM5A, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		}
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"cmp dword ptr [esi+0x64], eax") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAM6, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"pop dword ptr fs:[eax]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAM7, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

//-------------------------------------------------

//--------------- STUB AN ---------------------------

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov edx, 0x10c") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAN1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

//-------------------------------------------------


//--------------- STUB AO --------------------------

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov edx, dword ptr [ebx+0x64]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAO1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		}
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"push dword ptr fs:[eax]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAO2, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov dword ptr fs:[eax], esp") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAO3, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0xb09315f4") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAO4, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"cmp dword ptr [ebx+0x64], eax") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAO5, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"pop dword ptr fs:[eax]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAO6, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"cmp byte ptr [esi-0x6], 0x0") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAO7, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

//--------------------------------------------------------

//------------ STUB AP -------------------------

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov eax, 0x7b0") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAP1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

//---------------------------------------------

//----------- STUB AQ --------------------------

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov ebx, dword ptr [edx-0x16]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0x4552d021") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ2, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov dword ptr [ebp-0x4], eax") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ3, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"test dword ptr [ebx+0x2e8], 0x4") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ4, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0x9bdb51f0") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ5, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"cmp byte ptr [eax], 0xe9") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);


		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ6, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 

}

if(strcmp( (INS_Disassemble(ins).c_str() ),"cmp byte ptr [eax], 0xeb") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ7, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 	 
}


if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0xa5c44c50") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ8, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0xd0861aa4") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ9, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"lea ecx, ptr [ebp-0x14]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintRegAQ10, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		}
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"call dword ptr [ebx+0x2ec]") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);
		
		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ11, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"cmp dword ptr [ebp-0xc], 0x0") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);
		
		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ12, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov dword ptr [ebp-0x18], 0x0") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);
		
		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ13, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"call dword ptr [ebx+0x2ec]") == 0){ // two times 

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);
		
		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ14, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

if(strcmp( (INS_Disassemble(ins).c_str() ),"mov dword ptr [eax], 0x6") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);
		
		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)MyPrintRegAQ16, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
}

//----------------------------------------------------------

/*
if(strcmp( (INS_Disassemble(ins).c_str() ),"push 0x11") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);
		
		if(INS_HasFallThrough(ins)){
			INS_InsertCall(ins,IPOINT_AFTER,(AFUNPTR)MyPrintFakeStack1, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		}
}

*/
			
if(strcmp( (INS_Disassemble(ins).c_str() ),"or byte ptr [esp+0x1], 0x1") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		MYINFO("@@@@@@@@@@@@@@@@@@@@@@@@\n");
		printf("Ecco una push OR\n");
		
		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)PrintFs, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		//INS_Delete(ins);
  }	
} // End if HEAP code 
	//}

if(strcmp( (INS_Disassemble(ins).c_str() ),"or dword ptr [esp+0x1], 0x1") == 0){

		REGSET regsIn;
		REGSET_AddAll(regsIn);
		REGSET regsOut;
		REGSET_AddAll(regsOut);

		MYINFO("@@@@@@@@@@@@@@@@@@@@@@@@\n");
		printf("Ecco una push OR\n");
		
		INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)PrintFs, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,IARG_END); 
		INS_Delete(ins);
  }



	//----------- MAIN MODULE--------------------
	
	static int entry_point_passed = 0;

	if(curEip == 0x0041e000){
		entry_point_passed = 1;
	}

	MYINFO("[DEBUG] THREAD: %08x %08x %08x RTN: %s EIP: %08x INS: %s\n", PIN_GetTid() , PIN_ThreadId , PIN_GetParentTid(),RTN_FindNameByAddress(curEip).c_str(), curEip , INS_Disassemble(ins).c_str());


	if(entry_point_passed == 1){
	if(PIN_IsApplicationThread() == TRUE && pInfo->searchHeapMap(curEip)!=-1){
	MYINFO("@heap->		[DEBUG] THREAD: %08x %08x %08x RTN: %s EIP: %08x INS: %s\n", PIN_GetTid() , PIN_ThreadId , PIN_GetParentTid(),RTN_FindNameByAddress(curEip).c_str(), curEip , INS_Disassemble(ins).c_str());
	}
	else{
		if(curEip >= 0x00401000 && curEip <= 0x00436000){
			MYINFO("@MainModule->		[DEBUG] THREAD: %08x %08x %08x RTN: %s EIP: %08x INS: %s\n", PIN_GetTid() , PIN_ThreadId , PIN_GetParentTid(),RTN_FindNameByAddress(curEip).c_str(), curEip , INS_Disassemble(ins).c_str());
		}
		else{
			MYINFO("[DEBUG] THREAD: %08x %08x %08x RTN: %s EIP: %08x INS: %s\n", PIN_GetTid() , PIN_ThreadId , PIN_GetParentTid(),RTN_FindNameByAddress(curEip).c_str(), curEip , INS_Disassemble(ins).c_str());
		}
	}
	}


	// 1 - single instruction detection
	if(config->ANTIEVASION_MODE_INS_PATCHING && this->evasionPatcher.patchDispatcher(ins, curEip)){
		//MYINFO("Returned\n");
		return;
	}
	
	if(config->ANTIEVASION_MODE_SREAD){
	// 2 - memory read 
	// Checking if there is a read at addresses that the application shouldn't be aware of
	for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) {
		if (INS_MemoryOperandIsRead(ins,op)) {
			//if first read initialize the FakeMemoryHandler
			
			if(firstRead == 0){
				fakeMemH.initFakeMemory();
				firstRead=1;
			}
			
			REG scratchReg = GetScratchReg(op);
			
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(handleRead),
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, op,
				IARG_PTR, &fakeMemH,
				IARG_RETURN_REGS, scratchReg,
				IARG_END);
				
			INS_RewriteMemoryOperand(ins, op, scratchReg); 
		}
	  }
	}

	if(config->ANTIEVASION_MODE_SWRITE){
	//3. memory write filter	
	for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) {
		if(INS_MemoryOperandIsWritten(ins,op) && INS_IsMov(ins)){
			//MYINFO("Cur instruction %s ",INS_Disassemble(ins).c_str());
			REG writeReg = GetScratchReg(op);
			
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(handleWrite),
			IARG_INST_PTR,
			IARG_MEMORYOP_EA, op,
			IARG_PTR, &fakeWriteH,
			IARG_RETURN_REGS, writeReg, // this is an output param
			IARG_END);
				
			INS_RewriteMemoryOperand(ins, op, writeReg); 
			
		}	
	}	
  }
}
