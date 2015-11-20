#pragma once

#define DEBUG_BUILD 1
#define INFO_BUILD  1
#define WARN_BUILD  1
#define ERROR_BUILD 1
#define LOG_BUILD 1

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define DEBUG(fmt, ...) \
	do { if (DEBUG_BUILD) fprintf(stderr, "[DEBUG](%s):%d:%s(): " fmt, __FILENAME__, \
								__LINE__, __FUNCTION__, __VA_ARGS__); } while (0)


#define WARN(fmt, ...) \
	do { if (WARN_BUILD) fprintf(Log::getInstance()->getLogFile(),"[WARNING](%s) "fmt"\n",__FILENAME__, __VA_ARGS__);fflush(Log::getInstance()->getLogFile()); } while (0)

#define ERRORE(fmt, ...) \
	do { if (ERROR_BUILD) fprintf(Log::getInstance()->getLogFile(),"[ERROR](%s) "fmt"\n",__FILENAME__, __VA_ARGS__);fflush(Log::getInstance()->getLogFile()); } while (0)

#define INFO(fmt, ...) \
	do { if (LOG_BUILD){ fprintf(Log::getInstance()->getLogFile(),"[INFO](%s) "fmt"\n",__FILENAME__, __VA_ARGS__);fflush(Log::getInstance()->getLogFile()); } } while (0)

#define PRINT(fmt, ...) \
	do { if (LOG_BUILD){ fprintf(Log::getInstance()->getLogFile(),fmt"\n", __VA_ARGS__); } } while (0)

#define CLOSELOG()\
	do { if (LOG_BUILD){ Log::getInstance()->closeLogFile();}}while (0)



