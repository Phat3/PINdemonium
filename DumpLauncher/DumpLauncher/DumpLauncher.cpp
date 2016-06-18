#include "stdafx.h"
#include "PeLib.h"
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <list>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>


typedef struct {
	char * pdata;
	unsigned int virtual_address;
	unsigned int size;
}heap_zone;

std::list<heap_zone> heaps_zones;

void usage(char * program_name){
	printf("Usage: %s <dump folder> <dump_name>\n f.i.\n > DumpLauncher.exe C:\\pin\\2016\_06\_18\_03\_11\_40\\dump\_0[working]\ interheap_0.exe\n", program_name);
}

void abort(char * error_msg){
	printf("%s\n",error_msg);
	exit(-1);
}

PROCESS_INFORMATION spawnProcessSuspended(std::string full_path_dump){

	STARTUPINFO si ={0};
	PROCESS_INFORMATION pi ={0};

	std::wstring stemp = std::wstring(full_path_dump.begin(), full_path_dump.end());

	if(CreateProcess(stemp.c_str(), NULL,NULL,NULL,FALSE,NORMAL_PRIORITY_CLASS|CREATE_SUSPENDED,NULL,NULL,&si,&pi)){
		printf("[INFO] Process correctly spawned!\n");
		return pi;
	}
	else{
		abort("[ERROR] Process can't be spawned\n");
	}
}

FILE * existFile (std::string name) {

	FILE * file;
	if (file = fopen(name.c_str(), "r")) {
        return file;
    } else {
        return NULL;
    }   
}

unsigned int getHeapVA(std::string line){

	char address[8];
	int k=0;
	for(unsigned int i =0; i<=line.size();i++){
		char c = line.at(i);
		if(c != ' '){
			address[k] = c;
			k++;
		}else
			break;
	}
	address[k] = '\x00';


	// here we have in address all the digits of the virtual address
	std::string myaddress = std::string(address);

	return std::stoi (myaddress,nullptr,16); ;
}

unsigned int getHeapSize(std::string line){

	char size[30];
	int k=0;
	char c;
	unsigned int i;
	std::string l2;

	for(i=0; i<=line.size();i++){
		c = line.at(i);
		if(c != ' '){ // eating chars untill the next field 
			continue;
		}else{
			break;
		}
		
	}

	for(unsigned int j=i+1; j<=line.size();j++){
		c =  line.at(j);
		if(c != ' '){
			size[k] = c;
			k++;
		}
		else{
			break;
		}
	}
	     
	size[k] = '\x00';

	// here we have in address all the digits of the virtual address
	std::string mysize = std::string(size);

	return std::stoi (mysize,nullptr,16); ;
}

void allocateRemoteMemory(PROCESS_INFORMATION pi){

 SIZE_T n;

 unsigned int pid = GetProcessId(pi.hProcess);
 HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS,1,pid);

 unsigned int add ;

 for (std::list<heap_zone>::iterator it = heaps_zones.begin(); it != heaps_zones.end(); it++){
		
	 printf("Trying to allocate at %08x\n", it->virtual_address);

	 if(add = VirtualAllocEx(ph,NULL,it->size,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE) != NULL){

		 printf("Correctly allocated memory at %08x\n", it->virtual_address);
		 if(WriteProcessMemory(ph,(void *)add,it->pdata,it->size,&n)){
			 printf("Correctly copied data inside the remote address %08x\n",it->virtual_address);
		 }
		 else{
			printf("Something went wrong during the copying of data at the remote address %08x\n",it->virtual_address);
			
		 }
	 }
	 else{
		 printf("Something went wrong during allocation at %08x\n" , it->virtual_address);
		 printf("LAST ERROR %d\n", GetLastError());
	 }
 }
}

void collectHeapsData(std::string heaps_directory, std::string heap_map){

	std::string heap_dump = "heap_";
	unsigned int index = 0;
	unsigned int buffer_base_size = 1000;
	unsigned int buffer_size = 0;
	std::string full_heap_dump_path;
	FILE * f;

	std::ifstream  heap_map_file(heap_map.c_str());
	std::string line;

	do{
		full_heap_dump_path = heaps_directory + heap_dump + std::to_string((_ULonglong)index) + ".bin";
		f = existFile(full_heap_dump_path);

		if(f == NULL)
			break;
		else{
			// obtain file size:
			fseek (f , 0 , SEEK_END);
			long fsize = ftell (f);
			rewind (f);

			char * buffer = (char *)malloc(fsize);
			fread(buffer,1,fsize,f);

			std::getline(heap_map_file, line);
			
			heap_zone hz;
			hz.virtual_address = getHeapVA(line);
			//printf("Inserting the virtual address %08x\n" , hz.virtual_address);
			hz.size = getHeapSize(line);

			//printf("Inserting the heap with size %08x\n" , hz.size);

			hz.pdata= buffer;
		
			heaps_zones.push_back(hz);

			index++; // increasing the index to retrieve the next heap_$index.bin
		}
	}while(1); // untill there are any dumps 

	return;
}

int main(int argc, char* argv[])
{
	PROCESS_INFORMATION process_info;

	if(argc != 3){
		printf("argc is %d\n", argc);
		usage((char *)argv[0]);
		exit(0);
	}

	// Extracting the path from cmd_line
	std::string directory = std::string(argv[1]);
	std::string heaps_directory = directory + "heaps\\";
	std::string heap_map = heaps_directory + "heap_map.txt";
	std::string dump_name = std::string(argv[2]);
	std::string full_path_dump = directory + dump_name;

	// Collect binary data from dumped heaps 
	collectHeapsData(heaps_directory,heap_map);

	// Spawn the target process in suspended mode 
	process_info = spawnProcessSuspended(full_path_dump);


	// Now we have to allocate memory inside the spawned process
	allocateRemoteMemory(process_info);

	
	getchar();





}

