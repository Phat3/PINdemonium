#pragma once
class TimeTracker
{
public:
	TimeTracker(void);
	~TimeTracker(void);

	double GetStartInstrumentationCC();
	double GetEndInstrumentationCC();
	double GetStartDbiCC();
	double GetDelay();
	
	void SetStartInstrumentationCC(double cc);
	void SetEndInstrumentationCC(double cc);
	void SetDelay(double cc);
	void SetStartDbiCC(double cc);

	static TimeTracker* getInstance();


private:

	static TimeTracker* instance;
	double start_dbi_cc;
	double start_instrumentation_cc;
	double end_instrumentation_cc;
	double delay_cc;

};

