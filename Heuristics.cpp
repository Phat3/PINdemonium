#include "Heuristics.h"
#include "WriteIntervalHeuristics.h"
#include "ImageHeuristics.h"
#include "WriteInterval.h"
#include "OepFinder.h"
 
/*
The constructor of the Heuristics object add all our heuristics
in the array of struct for each granularity 

ADD HERE YOUR NEW HEURISTICS.

IMPLEMENT THE NEW HEURISTICS IN THE .cpp OF THE CORRESPONDING GRANULARITY: 

e.g.

IF YOU HAVE A NEW HEURISTIC FOR THE GRANULARITY WRITE INTERVAL ADD THE IMPLEMENTATIN
IN WriteIntervalHeuristics.cpp AND ITS SIGNATURE IN WriteIntervalHeuristics.h
*/
Heuristics::Heuristics(void){

	addWitemHeuristic("long jump" , test_heuristic);
	addImageHeuristic("dummy test" ,test_heuristic_2);
	//add here new heuristics 
}

Heuristics::~Heuristics(void){

}

BOOL Heuristics::callWitemHeuristics(INS ins , WriteInterval wi){
	
	UINT32 i,n_functions=0;
	std::vector<UINT32> test_result;

	n_functions = WriteIntervalHeuristics.size();

	for(i=0; i < n_functions; i++){
		test_result.push_back(WriteIntervalHeuristics[i].heuristic(ins , wi));
	}

	//[TODO] aggregate the result of the heuristics collected inside the test_result vector
	return FOUND_OEP;  
}


BOOL Heuristics::callImageHeuristics(){

	UINT32 i,n_functions=0;
	std::vector<UINT32> test_result;

	n_functions = ImageHeuristics.size();

	for(i=0; i < n_functions; i++){
		test_result.push_back(ImageHeuristics[i].heuristic());
	}

	//[TODO] aggregate the result of the heuristics collected inside the test_result vector
	return FOUND_OEP; 
}


BOOL Heuristics::addWitemHeuristic(const char *name , UINT32 (*heuristic)(INS ins ,WriteInterval wi)){

	 WitemHeuristic new_heuristic;

	 strncpy(new_heuristic.name,name,MAX_NAME_SIZE);
	 new_heuristic.heuristic = heuristic;
	 WriteIntervalHeuristics.push_back(new_heuristic);

	 return TRUE;
}


BOOL Heuristics::addImageHeuristic(const char *name , UINT32 (*heuristic)()){

	 ImageHeuristic new_heuristic;

	 strncpy(new_heuristic.name,name,MAX_NAME_SIZE);
	 new_heuristic.heuristic = heuristic;
	 ImageHeuristics.push_back(new_heuristic);

	 return TRUE;
}