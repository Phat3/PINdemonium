#pragma once

#define DEBUG_BUILD 1
#define INFO_BUILD  1
#define WARN_BUILD  1
#define ERROR_BUILD 1
#define LOG_BUILD 1

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define MYDEBUG(fmt, ...) \
	do { if (DEBUG_BUILD) fprintf(stderr, "[DEBUG](%s):%d:%s(): " fmt, __FILENAME__, \
								__LINE__, __FUNCTION__, __VA_ARGS__); } while (0)

#define MYWARN(fmt, ...) \
	do { if (WARN_BUILD) fprintf(Config::getInstance()->getLogFile(),"[WARNING](%s) "fmt"\n",__FILENAME__, __VA_ARGS__); } while (0)

#define MYERRORE(fmt, ...) \
	do { if (ERROR_BUILD) fprintf(Config::getInstance()->getLogFile(),"[ERROR](%s) "fmt"\n",__FILENAME__, __VA_ARGS__); } while (0)

#define MYINFO(fmt, ...) \
	do { if (LOG_BUILD){ fprintf(Config::getInstance()->getLogFile(),"[INFO](%s) "fmt"\n",__FILENAME__, __VA_ARGS__); } } while (0)

#define MYPRINT(fmt, ...) \
	do { if (LOG_BUILD){ fprintf(Config::getInstance()->getLogFile(),fmt"\n", __VA_ARGS__); } } while (0)

#define CLOSELOG()\
	do { if (LOG_BUILD){ Config::getInstance()->closeLogFile();}}while (0)



