#pragma once

#include "pin.H"
#include "WriteInterval.h"

#define MAX_NAME_SIZE 16
#define WRITE_INTERVAL_GRANULARITY 0
#define IMAGE_GRANULARITY 1
#define MAX_NUMBER_OF_HEURISTIC_FOR_GRANULARITY 10 

struct Heuristic
{
  char name[MAX_NAME_SIZE];
  BOOL (*heuristic)(INS ins, WriteInterval wi);
};

class Heuristics
{
public:
	Heuristics(void);
	~Heuristics(void);
	BOOL callWitemHeuristics(INS ins ,WriteInterval wi);
	BOOL callImageHeuristics(INS ins ,WriteInterval wi);

private:
	std::vector<Heuristic> WriteIntervalHeuristics; // vector of structs representing function to call on a WriteInterval
	std::vector<Heuristic> ImageHeuristics;  // vector of structs representing function to call on all the binary image
	
	BOOL addHeuristic(const char *name , UINT32 (*heuristic)(INS ins ,WriteInterval wi ) , UINT32 granularity); //add a new heuristic in the array of struct of WriteInterval or Image

};

