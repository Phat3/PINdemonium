#include "HeapModule.h"


HeapModule* HeapModule::instance = 0;

HeapModule::HeapModule(void){
}

HeapModule* HeapModule::getInstance(){
if (instance == 0)
	instance = new HeapModule();

return instance;
}

UINT32 HeapModule::checkHeapWxorX(WriteInterval* item, ADDRINT curEip, int dumpAndFixResult){

		// include in the PE the dump of the current heap zone in which we have break the WxorX 
	if( item->getHeapFlag() && dumpAndFixResult != SCYLLA_ERROR_FILE_FROM_PID  && dumpAndFixResult != SCYLLA_ERROR_DUMP ){
		MYPRINT("[INFO][OepFinder.cpp] - EIP ON THE HEAP - DUMPING THE HEAP-ZONE BEGIN 0x%08x | END 0x%08x", item->getAddrBegin(),item->getAddrEnd());
		unsigned char * Buffer;
		UINT32 size_write_set = item->getAddrEnd() - item->getAddrBegin();
		//prepare the buffer to copy inside the stuff into the heap section to dump 		  
		Buffer = (unsigned char *)malloc( size_write_set );
		// copy the heap zone into the buffer 
		PIN_SafeCopy(Buffer , (void const *)item->getAddrBegin() , size_write_set);	
		ScyllaWrapperInterface *scylla_wrapper = ScyllaWrapperInterface::getInstance();
		// get the name of the last dump from the Config object 
		Config *config = Config::getInstance();
		string dump_path = config->getWorkingDumpPath();

		if(dumpAndFixResult != 0){
			dump_path = dump_path + "_dmp";
		}

		if(!Helper::existFile(dump_path)){ // this is the case in which we have a not working dump but we want to add anyway the .heap 
			dump_path = config->getNotWorkingDumpPath();
		}
		if(!Helper::existFile(dump_path)){
			MYINFO("[CRITICAL ERROR]Dump file not found\n");
			return OEPFINDER_HEURISTIC_FAIL;
		}
		// and convert it into the WCHAR representation 
		std::wstring widestr = std::wstring(dump_path.begin(), dump_path.end());
		const wchar_t* widecstr = widestr.c_str();
		// calculate where the program jump in the heap ( i.e. 0 perfectly at the begin of the heapzone ) 
		UINT32 offset = curEip - item->getAddrBegin();
		//REMEMEBER TO LOAD AND UNLOAD SCYLLAWRAPPER!
		scylla_wrapper->loadScyllaLibary();
		scylla_wrapper->ScyllaWrapAddSection(widecstr, ".heap" ,size_write_set , offset , Buffer);
		scylla_wrapper->unloadScyllaLibrary();
		free(Buffer);
	}
	else{
	  MYPRINT("[INFO][OepFinder.cpp] - [WARN] EIP IS NOT ON THE HEAP\n");
	}

	return 0;
}

VOID HeapModule::saveHeapZones(std::map<std::string,HeapZone> hzs, std::map<std::string,std::string> hzs_dumped){

	MYPRINT("[INFO][OepFinder.cpp] - SAVING ALL THE HEAP-ZONES ALLOCATED UNTIL NOW: %d HEAP-ZONES\n", hzs.size());
	std::string heaps_dir = Config::getInstance()->getWorkingDir() + "\\heaps";
	_mkdir(heaps_dir.c_str()); // create the folder we will store the .bin of the heap zones 

	char *hz_data;
	std::string hz_md5;
	std::string hz_md5_now;
	Config *config = Config::getInstance();

	std::string heap_map_path = heaps_dir + "\\" +  "heap_map.txt";
	std::ofstream heap_map_file(heap_map_path);

	for (std::map<std::string,HeapZone>::iterator it=hzs.begin(); it!=hzs.end(); ++it){	
		HeapZone hz = it->second;
		std::string mem_hz_md5 = it->first;
		hz_data = (char *)malloc(hz.size);
		PIN_SafeCopy(hz_data , (void const *)hz.begin , hz.size);
		hz_md5_now = md5(hz_data); // take the md5 of the data inside the heap 

		std::map<std::string,std::string>::iterator hz_dumped_it = hzs_dumped.find(hz_md5_now);

		if(hz_dumped_it != hzs_dumped.end()){
			// an heapzone with these data has already been dumped
			MYPRINT("HEAPZONE [POSITION (BEGIN 0x%08x | END 0x%08x) - DATA MD5 %s] ALREADY DUMPED! - CREATING HARD LINKS", hz.begin,hz.end, hz_md5_now.c_str());
			std::string heap_link_name = linkHZ(hz_dumped_it->second);
			logHZ(heap_link_name,hz,hz_md5);
		}else{
			MYPRINT("HEAPZONE [POSITION (BEGIN 0x%08x | END 0x%08x) - DATA MD5 %s] TO DUMP! - CREATING DUMP AND HARD LINKS", hz.begin,hz.end, hz_md5_now.c_str());
			std::string heap_bin_path  = dumpHZ(hz,hz_data,hz_md5_now);
			std::string heap_link_name = linkHZ(heap_bin_path);
			logHZ(heap_link_name,hz,hz_md5_now);
			ProcInfo *pInfo = ProcInfo::getInstance();
			pInfo->insertDumpedHeapZone(hz_md5_now,heap_bin_path);
		}
	}
}


std::string HeapModule::dumpHZ(HeapZone hz, char * data, std::string hz_md5){

	std::string heap_dir_path = Config::getInstance()->getHeapDir();
	std::string heap_bin_name = "heap_" + hz_md5 + ".bin";
	std::string heap_bin_path = heap_dir_path + "\\" + heap_bin_name; // this is the heap.bin in the global folder HEAP

	// dump of the heap inside this folder 
	std::string heap_dir = Config::getInstance()->getHeapDir();
	std::ofstream heap_file(heap_bin_path, std::ios::binary);

	heap_file.write((char *) data, hz.size);
	heap_file.close();

	return heap_bin_path;
}


std::string HeapModule::linkHZ(std::string heap_bin_path){

	// we will save the link to the heap.bin inside the folder heaps of the currente dump 
	std::string heaps_dir = Config::getInstance()->getWorkingDir() + "\\heaps";

	// creating the name of the link by extracting the name of the heap.bin 
	std::size_t pos = heap_bin_path.find("heap_");
	std::string heap_link_name = heap_bin_path.substr(pos);

	// finally composing the heap link path
	std::string heap_link_path = heaps_dir + "\\" + heap_link_name;

	W::CreateHardLink(heap_link_path.c_str() , heap_bin_path.c_str() ,NULL);

	return  heap_link_name;
}

void HeapModule::logHZ(std::string heap_link_name, HeapZone hz, std::string hz_md5){

	// open the heap_map.txt
	std::string working_dir = Config::getInstance()->getWorkingDir();  
	std::string heap_map_path = working_dir + "\\heaps" +  "\\heap_map.txt"; // write the log 

	//printf("Inside logHZ - heap_map_path: %s\n", heap_map_path.c_str());

	std::ofstream heap_map_file(heap_map_path,ios::app);

	heap_map_file << heap_link_name << " " << std::hex << hz.begin << " " << std::to_string((_ULonglong)hz.size) << " " << "\n" ;

	heap_map_file.close();
}