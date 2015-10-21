#include "ProcInfo.h"
#include "Log.h"
#include "Debug.h"

ProcInfo* ProcInfo::instance = 0;

ADDRINT prev_ip = 0;


ProcInfo* ProcInfo::getInstance()
{
	if (instance == 0)
		instance = new ProcInfo;
	return instance;
}


ProcInfo::~ProcInfo(void)
{
}


/* Setter */

/*
Save the initial registers inside the struct
You can fine the macro fo the registers at:
https://software.intel.com/sites/landingpage/pintool/docs/49306/Pin/html/group__REG__CPU__IA32.html
*/
void ProcInfo::setStartRegContext(CONTEXT * ctx){

	this->reg_start_context.eax = PIN_GetContextReg(ctx,REG_EAX);
	this->reg_start_context.ebx = PIN_GetContextReg(ctx,REG_EBX);
	this->reg_start_context.ecx = PIN_GetContextReg(ctx,REG_ECX);
	this->reg_start_context.edx = PIN_GetContextReg(ctx,REG_EDX);
	this->reg_start_context.esp = PIN_GetContextReg(ctx,REG_ESP);
	this->reg_start_context.ebp = PIN_GetContextReg(ctx,REG_EBP);
	this->reg_start_context.edi = PIN_GetContextReg(ctx,REG_EDI);
	this->reg_start_context.esi = PIN_GetContextReg(ctx,REG_ESI);

}

/*
Save the current registers inside the struct
You can fine the macro fo the registers at:
https://software.intel.com/sites/landingpage/pintool/docs/49306/Pin/html/group__REG__CPU__IA32.html
*/
void ProcInfo::setCurrRegContext(CONTEXT * ctx){

	this->reg_curr_context.eax = PIN_GetContextReg(ctx,REG_EAX);
	this->reg_curr_context.ebx = PIN_GetContextReg(ctx,REG_EBX);
	this->reg_curr_context.ecx = PIN_GetContextReg(ctx,REG_ECX);
	this->reg_curr_context.edx = PIN_GetContextReg(ctx,REG_EDX);
	this->reg_curr_context.esp = PIN_GetContextReg(ctx,REG_ESP);
	this->reg_curr_context.ebp = PIN_GetContextReg(ctx,REG_EBP);
	this->reg_curr_context.edi = PIN_GetContextReg(ctx,REG_EDI);
	this->reg_curr_context.esi = PIN_GetContextReg(ctx,REG_ESI);
}

void ProcInfo::setFirstINSaddress(ADDRINT address){
	this->first_instruction  = address;
}

void ProcInfo::setPrevIp(ADDRINT ip){
	this->prev_ip  = ip;
}

/* Getter */
RegContext ProcInfo::getStartRegContext(){
	return this->reg_start_context;
}

RegContext ProcInfo::getCurrRegContext(){
	return this->reg_curr_context;
}

ADDRINT ProcInfo::getFirstINSaddress(){
	return this->first_instruction;
}

ADDRINT ProcInfo::getPrevIp(){
	return this->prev_ip;
}

std::vector<Section> ProcInfo::getSections(){
	return this->Sections;
}



/* Utils + Helper */
void ProcInfo::PrintStartContext(){
	MYLOG("======= START REGISTERS ======= \n");
	MYLOG("EAX: %08x " , this->reg_start_context.eax);
	MYLOG("EBX: %08x " , this->reg_start_context.ebx);
	MYLOG("ECX: %08x " , this->reg_start_context.ecx);
	MYLOG("EDX: %08x " , this->reg_start_context.edx);
	MYLOG("ESP: %08x " , this->reg_start_context.esp);
	MYLOG("EBP: %08x " , this->reg_start_context.ebp);
	MYLOG("ESI: %08x " , this->reg_start_context.esi);
	MYLOG("EDI: %08x " , this->reg_start_context.edi);
	MYLOG("============================== \n");
}

void ProcInfo::PrintCurrContext(){

	MYLOG("======= CURRENT REGISTERS ======= \n");
	MYLOG("EAX: %08x " , this->reg_curr_context.eax);
	MYLOG("EBX: %08x " , this->reg_curr_context.ebx);
	MYLOG("ECX: %08x " , this->reg_curr_context.ecx);
	MYLOG("EDX: %08x " , this->reg_curr_context.edx);
	MYLOG("ESP: %08x " , this->reg_curr_context.esp);
	MYLOG("EBP: %08x " , this->reg_curr_context.ebp);
	MYLOG("ESI: %08x " , this->reg_curr_context.esi);
	MYLOG("EDI: %08x " , this->reg_curr_context.edi);
	MYLOG("================================= \n");
}

void ProcInfo::PrintSections(){
	MYLOG("======= SECTIONS ======= \n");
	for(int i = 0; i < this->Sections.size(); i++) {
		Section item = this->Sections.at(i);
		MYLOG("%s	->	begin : %08x		end : %08x", item.name.c_str(), item.begin, item.end);
	}
	MYLOG("================================= \n");
}

//insert a new section in our structure
void ProcInfo::insertSection(Section section){
	this->Sections.push_back(section);
}

//return the section's name where the IP resides
string ProcInfo::getSectionNameByIp(ADDRINT ip){
	string s = "";
	for(int i = 0; i < this->Sections.size(); i++) {
		Section item = this->Sections.at(i);
		if(ip >= item.begin && ip <= item.end){
			s = item.name;
		}
	}
	return s;
}


float ProcInfo::GetEntropy(){

	IMG binary_image = APP_ImgHead();

	const double d1log2 = 1.4426950408889634073599246810023;
	double Entropy = 0.0;
	unsigned long Entries[256];
	unsigned char* Buffer;

	ADDRINT start_address = IMG_LowAddress(binary_image);
	ADDRINT end_address = IMG_HighAddress(binary_image);
	UINT32 size = end_address - start_address;

	Buffer = (unsigned char *)malloc(size);

	MYLOG("size to dump is %d" , size);
	MYLOG("Start address is %08x" , start_address);
	MYLOG("Start address is %08x" , end_address);
	MYLOG("IMAGE NAME IS %s" , IMG_Name(binary_image));

	PIN_SafeCopy(Buffer , (void const *)start_address , size);

	memset(Entries, 0, sizeof(unsigned long) * 256);

	for (unsigned long i = 0; i < size; i++)
		Entries[Buffer[i]]++;
	for (unsigned long i = 0; i < 256; i++)
	{
		double Temp = (double) Entries[i] / (double) size;
		if (Temp > 0)
			Entropy += - Temp*(log(Temp)*d1log2); 
	}

	MYLOG("ENTROPY IS %f" , Entropy);

	return Entropy;
}


float ProcInfo::getInitialEntropy(){

	return this->InitialEntropy;

}

void ProcInfo::setInitialEntropy(float Entropy){
	
	this->InitialEntropy = Entropy;

}