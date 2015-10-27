#include "ProcInfo.h"

ProcInfo* ProcInfo::instance = 0;

ProcInfo* ProcInfo::getInstance()
{
	if (instance == 0)
		instance = new ProcInfo();
		
	return instance;
}


ProcInfo::ProcInfo()
{
	this->prev_ip = 0;
	this->popad_flag = FALSE;
	this->pushad_flag = FALSE;
}

ProcInfo::~ProcInfo(void)
{
}


/* ----------------------------- SETTER -----------------------------*/

void ProcInfo::setFirstINSaddress(ADDRINT address){
	this->first_instruction  = address;
}

void ProcInfo::setPrevIp(ADDRINT ip){
	this->prev_ip  = ip;
}

void ProcInfo::setPushadFlag(BOOL flag){
	this->pushad_flag = flag;
}


void ProcInfo::setPopadFlag(BOOL flag){
	this->popad_flag = flag;
}


void ProcInfo::setProcName(string name){
	//get the starting position of the last element of the path (the exe name)
	int pos_exe_name = name.find_last_of("\\");
	string exe_name = name.substr(pos_exe_name + 1);
	//get the name from the last occurrence of / till the end of the string minus the file extension
	this->proc_name =  exe_name.substr(0, exe_name.length() - 4);
}

void ProcInfo::setInitialEntropy(float Entropy){
	this->InitialEntropy = Entropy;
}

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



/* ----------------------------- GETTER -----------------------------*/

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

BOOL ProcInfo::getPushadFlag(){
	return this->pushad_flag ;
}

BOOL ProcInfo::getPopadFlag(){
	return this->popad_flag;
}

string ProcInfo::getProcName(){
	return this->proc_name;
}

float ProcInfo::getInitialEntropy(){
	return this->InitialEntropy;
}



/* ----------------------------- PUBLIC METHODS -----------------------------*/

void ProcInfo::PrintStartContext(){

	MYINFO("======= START REGISTERS ======= \n");
	MYINFO("EAX: %08x " , this->reg_start_context.eax);
	MYINFO("EBX: %08x " , this->reg_start_context.ebx);
	MYINFO("ECX: %08x " , this->reg_start_context.ecx);
	MYINFO("EDX: %08x " , this->reg_start_context.edx);
	MYINFO("ESP: %08x " , this->reg_start_context.esp);
	MYINFO("EBP: %08x " , this->reg_start_context.ebp);
	MYINFO("ESI: %08x " , this->reg_start_context.esi);
	MYINFO("EDI: %08x " , this->reg_start_context.edi);
	MYINFO("============================== \n");

}

void ProcInfo::PrintCurrContext(){

	MYINFO("======= CURRENT REGISTERS ======= \n");
	MYINFO("EAX: %08x " , this->reg_curr_context.eax);
	MYINFO("EBX: %08x " , this->reg_curr_context.ebx);
	MYINFO("ECX: %08x " , this->reg_curr_context.ecx);
	MYINFO("EDX: %08x " , this->reg_curr_context.edx);
	MYINFO("ESP: %08x " , this->reg_curr_context.esp);
	MYINFO("EBP: %08x " , this->reg_curr_context.ebp);
	MYINFO("ESI: %08x " , this->reg_curr_context.esi);
	MYINFO("EDI: %08x " , this->reg_curr_context.edi);
	MYINFO("================================= \n");

}

void ProcInfo::PrintSections(){

	MYINFO("======= SECTIONS ======= \n");
	for(unsigned int i = 0; i < this->Sections.size(); i++) {
		Section item = this->Sections.at(i);
		MYINFO("%s	->	begin : %08x		end : %08x", item.name.c_str(), item.begin, item.end);
	}
	MYINFO("================================= \n");

}

//insert a new section in our structure
void ProcInfo::insertSection(Section section){
	this->Sections.push_back(section);
}

//return the section's name where the IP resides
string ProcInfo::getSectionNameByIp(ADDRINT ip){

	string s = "";
	for(unsigned int i = 0; i < this->Sections.size(); i++) {
		Section item = this->Sections.at(i);
		if(ip >= item.begin && ip <= item.end){
			s = item.name;
		}
	}
	return s;

}

//return the entropy value of the entire program
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

	MYINFO("size to dump is %d" , size);
	MYINFO("Start address is %08x" , start_address);
	MYINFO("Start address is %08x" , end_address);
	MYINFO("IMAGE NAME IS %s" , IMG_Name(binary_image));

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

	MYINFO("ENTROPY IS %f" , Entropy);

	return Entropy;
}



