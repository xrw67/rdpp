#ifndef _RDPP_CORE_LOG_H_
#define _RDPP_CORE_LOG_H_

#include <core/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace rdpp {

    enum LogLevel {
	    LOGLEVEL_TRACE,
	    LOGLEVEL_DEBUG,
	    LOGLEVEL_INFO,
	    LOGLEVEL_WARN,
	    LOGLEVEL_ERROR,
	    LOGLEVEL_FATAL,
	    LOGLEVEL_NUM_LOG_LEVELS
    };

    namespace detail {

        // 从路径中得到文件名 
        inline const char *getFileNameFromPath(const char *pathName)
        {
	        const char* slash = strrchr(pathName, '/');
	        if (slash) {
		        return slash + 1;
	        } else {
		        const char *bslash = strrchr(pathName, '\\');
		        if (bslash) {
			        return bslash + 1;
		        }
	        }
	        return pathName;
        }

        class LogFinisher;

        class LogMessage 
        {
        public:
	        LogMessage(LogLevel level, const char *tag, const char *filename, int line);
	        ~LogMessage();

	        LogMessage &operator<<(const string &value);
	        LogMessage &operator<<(const char *value);
	        LogMessage &operator<<(char value);
	        LogMessage &operator<<(int value);
	        LogMessage &operator<<(unsigned int value);
	        LogMessage &operator<<(long value);
	        LogMessage &operator<<(unsigned long value);
	        LogMessage &operator<<(long long value);
	        LogMessage &operator<<(unsigned long long value);
	        LogMessage &operator<<(double value);
	        LogMessage &operator<<(const void *p);

        private:
	        friend class LogFinisher;
	        friend class LogTraceFunction;
	        void finish();

	        LogLevel _level;
	        string _message;
        };

        class LogFinisher
        {
        public:
	        void operator=(LogMessage &other);
        };

    } // namespace detail

	typedef rdpp::function<void(const string &)> LogHandler;

	void setLogHandler(LogHandler newFunc);

    void setLogLevel(const char *tag, LogLevel level);
    LogLevel logLevel(const char *tag);

    #undef ERROR

    #define RDPP_LOG(TAG, LEVEL) if (rdpp::logLevel(TAG) <= rdpp::LOGLEVEL_##LEVEL) \
	    rdpp::detail::LogFinisher() =                                               \
		    rdpp::detail::LogMessage(rdpp::LOGLEVEL_##LEVEL, TAG,                   \
				rdpp::detail::getFileNameFromPath(__FILE__), __LINE__)
    #define RDPP_LOG_IF(TAG, LEVEL, CONDITION) \
	    !(CONDITION) ? (void)0 : RDPP_LOG(TAG, LEVEL)

	class Buffer;
	string hexdump(const Buffer &s);
	string hexdump(const Buffer *s);
	string hexdump(const string &s);
	string hexdump(const void *data, size_t len);

} // namespace rdpp

#endif // _RDPP_CORE_LOG_H_
