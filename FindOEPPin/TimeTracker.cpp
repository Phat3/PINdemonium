#include "TimeTracker.h"


TimeTracker* TimeTracker::instance = 0;

TimeTracker* TimeTracker::getInstance()
{
	if (instance == 0)
		instance = new TimeTracker();
		
	return instance;
}



TimeTracker::TimeTracker(void)
{
	start_instrumentation_cc = 0;
	end_instrumentation_cc = 0;
	delay_cc = 0;
}





TimeTracker::~TimeTracker(void)
{
}


double TimeTracker::GetStartInstrumentationCC(){

	return start_instrumentation_cc;
}

double TimeTracker::GetEndInstrumentationCC(){
	return end_instrumentation_cc;
}

double TimeTracker::GetDelay(){
	return delay_cc;
}

double TimeTracker::GetStartDbiCC(){
	return start_dbi_cc;
}

void TimeTracker::SetStartInstrumentationCC(double cc){
	
	start_instrumentation_cc = cc;
}

void TimeTracker::SetEndInstrumentationCC(double cc){
	
	end_instrumentation_cc = cc;
}


void TimeTracker::SetDelay(double cc){

	delay_cc = delay_cc + cc;
}


void TimeTracker::SetStartDbiCC(double cc){
	start_dbi_cc = cc;
}
