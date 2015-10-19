#pragma once

#define DEBUG_BUILD 1
#define INFO_BUILD  1
#define WARN_BUILD  1
#define ERROR_BUILD 1
#define LOG_BUILD 1



#define MYDEBUG(fmt, ...) \
		do { if (DEBUG_BUILD) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
								__LINE__, __FUNCTION__, __VA_ARGS__); } while (0)

#define MYINFO(fmt, ...) \
			do { if (INFO_BUILD) fprintf(stderr,"[INFO] "fmt, __VA_ARGS__); } while (0)


#define MYWARN(fmt, ...) \
			do { if (WARN_BUILD) fprintf(stderr,"[WARNING] "fmt, __VA_ARGS__); } while (0)

#define MYERRORE(fmt, ...) \
			do { if (ERROR_BUILD) fprintf(stderr,"[ERROR] "fmt, __VA_ARGS__); } while (0)

#define MYLOG(fmt, ...) \
	do { if (LOG_BUILD){ fprintf(Log::getInstance()->getLogFile(),"[INFO] "fmt"\n", __VA_ARGS__);} } while (0)

#define CLOSELOG()\
	do { if (LOG_BUILD){ Log::getInstance()->closeLogFile();}}while (0)



