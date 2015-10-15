#include "pin.H"
#include "WriteInterval.h"
#include "OepFinder.h"

UINT32 test_heuristic_2(){

	MYLOG("NOT AWESOME");
	return FOUND_OEP;

}


UINT32 GetEntropy(IMG binary_image){

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

	memcpy(Buffer, (void const * )start_address, size);

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

	return -1;
}