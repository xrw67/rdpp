#include <core/log.h>
#include <core/string_util.h>
#include <core/timestamp.h>
#include <core/buffer.h>
#include <algorithm>
#include <map>

namespace rdpp {
	namespace detail {


		// 日志级别
		const char* LogLevelName[LOGLEVEL_NUM_LOG_LEVELS] = {
			"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL",
		};

		//默认的日志输出函数
		void nullLogHandler(const string &message)
		{
			// Nothing.
		}

		static LogLevel g_logLevel = LOGLEVEL_TRACE;
		static LogHandler g_logHandler = nullLogHandler;
		static std::map<std::string, LogLevel> g_logTags;


		// 高效的整型转字符串算法 by Matthew Wilson.
		const char digits[] = "9876543210123456789";
		const char* zero = digits + 9;
		const char digitsHex[] = "0123456789ABCDEF";

		template<typename T>
		inline size_t convert(char buf[], T value)
		{
			T i = value;
			char* p = buf;

			do {
				int lsd = static_cast<int>(i % 10);
				i /= 10;
				*p++ = zero[lsd];
			} while (i != 0);

			if (value < 0)
				*p++ = '-';
			*p = '\0';
			std::reverse(buf, p);

			return p - buf;
		}

		inline size_t convertHex(char buf[], uintptr_t value)
		{
			uintptr_t i = value;
			char* p = buf;

			do {
				int lsd = static_cast<int>(i % 16);
				i /= 16;
				*p++ = digitsHex[lsd];
			} while (i != 0);

			*p = '\0';
			std::reverse(buf, p);

			return p - buf;
		}

		LogMessage::LogMessage(LogLevel level, const char *tag, const char *filename, int line)
			: _level(level)
		{
			*this << "[" 
				<< Timestamp::now().toFormatString() << " "
				<< LogLevelName[level] << " "
				<< filename << ":" << line << " "
				<< tag
				<< "] ";
		}

		LogMessage::~LogMessage()
		{}

		LogMessage &LogMessage::operator<<(const string &value)
		{
			_message += value;
			return *this;
		}

		LogMessage &LogMessage::operator<<(const char* value)
		{
			_message += value;
			return *this;
		}

		#undef DECLARE_STREAM_FORMAT_INTEGER
		#define DECLARE_STREAM_FORMAT_INTEGER(TYPE)                \
			LogMessage& LogMessage::operator<<(TYPE value)         \
			{                                                      \
				char buffer[128];                                  \
				convert<TYPE>(buffer, value);     \
				buffer[sizeof(buffer) - 1] = '\0';                 \
				_message += buffer;                                \
				return *this;                                      \
			}

		DECLARE_STREAM_FORMAT_INTEGER(char)
		DECLARE_STREAM_FORMAT_INTEGER(int)
		DECLARE_STREAM_FORMAT_INTEGER(unsigned int)
		DECLARE_STREAM_FORMAT_INTEGER(long)
		DECLARE_STREAM_FORMAT_INTEGER(unsigned long)
		DECLARE_STREAM_FORMAT_INTEGER(long long)
		DECLARE_STREAM_FORMAT_INTEGER(unsigned long long)
		#undef DECLARE_STREAM_OPERATOR

		LogMessage &LogMessage::operator<<(double value)
		{
			char buffer[128];
			snprintf(buffer, sizeof(buffer), "%g", value);
			buffer[sizeof(buffer) - 1] = '\0';
			_message += buffer;
			return *this;
		}

		LogMessage &LogMessage::operator<<(const void* p)
		{
			uintptr_t v = reinterpret_cast<uintptr_t>(p);
			char buffer[128];
			buffer[0] = '0';
			buffer[1] = 'x';
			convertHex(buffer + 2, v);
			buffer[sizeof(buffer) - 1] = '\0';
			_message += buffer;
			return *this;
		}

		void LogMessage::finish() 
		{
			g_logHandler(_message);

			if (LOGLEVEL_FATAL == _level)
				abort();
		}

		void LogFinisher::operator=(LogMessage& other)
		{
			other.finish();
		}

	} // namespace detail

	// 设置日志写函数
	void setLogHandler(LogHandler newFunc)
	{
		if (NULL == newFunc) {
			detail::g_logHandler = rdpp::bind(detail::nullLogHandler, _1);
		} else {
			detail::g_logHandler = newFunc;
		}
	}

	// 设置日志级别
	void setLogLevel(const char *tag, LogLevel level)
	{
		if (tag == NULL) {
			detail::g_logLevel = level;
			std::map<std::string, LogLevel>::iterator it;
			for (it = detail::g_logTags.begin(); it != detail::g_logTags.end(); ++it)
				it->second = level;
		} else {
			detail::g_logTags[tag] = level;
		}
	}

	LogLevel logLevel(const char *tag)
	{
		std::map<std::string, LogLevel>::iterator it = detail::g_logTags.find(tag);
		if (it != detail::g_logTags.end()) {
			return it->second;
		} else {
			detail::g_logTags[tag] = detail::g_logLevel;
			return detail::g_logLevel;
		}
	}

	string hexdump(const Buffer &s)
	{
		return hexdump(s.data(), s.length());
	}
	
	string hexdump(const Buffer *s)
	{
		return hexdump(s->data(), s->length());
	}

	string hexdump(const string &data)
	{
		return hexdump(data.c_str(), data.length());
	}

	string hexdump(const void *data, size_t len)
	{
		static char *b2h = "0123456789ABCDEF";
		string output = StringUtil::format("\nhexdump(addr:0x%x, len:%d):\n", data, len);
		const char *_data = (const char *)data;
		unsigned char line[48 + 16 + 1]; // each line
		int pos, linesize;
		char c;

		for (size_t i = 0; i < len; i += 16) {
			if (len - i < 16)
				linesize = len - i;
			else
				linesize = 16;

			memset(line, ' ', sizeof(line));
			pos = 0;

			for (int j = 0; j < 16; j++) {
				c = _data[i+j];

				if (j < linesize) {
					line[pos] = b2h[(c & 0xf0) >> 4];
					line[pos+1] = b2h[c & 0x0f];
				}

				pos += 3;
			}

			for (int j = 0; j < linesize; j++) {
				c = _data[i+j];

				if (c >= 0x20 && c <= 0x7e)
					line[pos++] = c;
				else
					line[pos++] = '.';
			}

			line[pos] = '\0';

			output += StringUtil::format("%04X: %s\n", i, line);
		}
		return output;
	}

} // namespace rdpp
