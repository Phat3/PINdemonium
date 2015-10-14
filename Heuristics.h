#pragma once

#include "pin.H"
#include "WriteInterval.h"

#define MAX_NAME_SIZE 16
#define MAX_NUMBER_OF_HEURISTIC_FOR_GRANULARITY 10 

struct WitemHeuristic
{
  char name[MAX_NAME_SIZE];
  UINT32 (*heuristic)(INS ins, WriteInterval wi);
};

struct ImageHeuristic
{
  char name[MAX_NAME_SIZE];
  UINT32 (*heuristic)();
};

class Heuristics
{
public:
	Heuristics(void);
	~Heuristics(void);
	BOOL callWitemHeuristics(INS ins ,WriteInterval wi);
	BOOL callImageHeuristics();

private:
	std::vector<WitemHeuristic> WriteIntervalHeuristics; // vector of structs representing function to call on a WriteInterval
	std::vector<ImageHeuristic> ImageHeuristics;  // vector of structs representing function to call on all the binary image
	
	BOOL addWitemHeuristic(const char *name , UINT32 (*heuristic)(INS ins ,WriteInterval wi )); //add a new heuristic in the array of struct of WriteInterval or Image
	BOOL addImageHeuristic(const char *name , UINT32 (*heuristic)(void)); 
};

