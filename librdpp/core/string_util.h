#ifndef _RDPP_CORE_STRING_UTIL_H_
#define _RDPP_CORE_STRING_UTIL_H_

#include <core/config.h>
#include <cstdarg>

namespace rdpp {

    class StringUtil
    {
    public:
		static const int kMaxStringLen = 64 * 1024;

		/// @brief 格式化字符串
		static string format(const char *format, ...)
		{
			va_list ap;
			va_start(ap, format);
			string str;
		
			char *buf = (char *)malloc(kMaxStringLen);
			if (buf) {
				vsnprintf(buf, kMaxStringLen, format, ap);
				str = buf;
				free(buf);
				va_end(ap);
			}
			return str;
		}

		 /// @brief 转换成int类型
		static int stoi(const string &str) 
		{ 
			return (0 == str.length()) ? 0 : atoi(str.c_str());
		}

		/// @brief 转换成unsigned int
		static unsigned int stoui(const string &str) 
		{ 
			return (0 == str.length()) ? 0 : static_cast<unsigned int>(atoi(str.c_str()));
		} 

		/// @brief 转换成int64类型
		static int64_t stoi64(const std::string &str) 
		{
			int64_t v = 0;
	#ifdef WIN32
			sscanf(str.c_str(), "%I64d", &v);
	#else
			sscanf(str.c_str(), "%lld", &v);
	#endif
			return v;
		}
	
		/// @brief转换成uint64类型
		static int64_t stoui64(const std::string &str) 
		{
			int64_t v = 0;
	#ifdef WIN32
			sscanf(str.c_str(), "%I64u", &v);
	#else
			sscanf(str.c_str(), "%llu", &v);
	#endif
			return v;
		}
	
		/// @brief 转换成long
		static long stol(const string &str) 
		{ 
			return (0 == str.length()) ? 0L : atol(str.c_str()); 
		}

		/// @brief 转换成float
		static float stof(const string &str)
		{ 
			return (0 == str.length()) ? 0.0f : static_cast<float>(atof(str.c_str())); 
		}

		/// @brief 转换成double
		static double stod(const string &str) 
		{ 
			return (0 == str.length()) ? 0.0 : atof(str.c_str()); 
		}

		/// @brief 转换成bool
		static bool stob(const string &str) 
		{ 
			return (0 == str.length() || str == "0" || str == "false" || str == "FALSE") ? false : true; 
		}

		/// @brief 将int类型数据转成字符串
		static string toString(const int val)
		{
			char buf[32] = {0};
			snprintf(buf, sizeof(buf), "%d", val);
			return buf;
		}

		/// @brief 将unsigned int类型数据转成字符串
		static string toString(const unsigned int val)
		{
			char buf[32] = {0};
			snprintf(buf, sizeof(buf), "%u", val);
			return buf;
		}

		/// @brief 将long类型数据转成字符串
		static string toString(const long val)
		{
			char buf[32] = {0};
			snprintf(buf, sizeof(buf), "%ld", val);
			return buf;
		}

		/// @brief 将long long类型数据转成字符串
		static string toString(const long long val)
		{
			char buf[32] = {0};
			snprintf(buf, sizeof(buf), "%lld", val);
			return buf;
		}

		/// @brief 将double类型数据转成字符串
		static string toString(const double val)
		{
			char buf[32] = {0};
			snprintf(buf, sizeof(buf), "%f", val);
			return buf;
		}

		/// @brief 将bool类型数据转成字符串
		static string toString(const bool val)
		{
			return val ? "1" : "0";
		}

        /// @brief 转成大写字母
        static string upper(const string &str)
        {
            string s(str);
            for (string::size_type i = 0; i < s.length(); ++i)
                if (s[i] >= 'a' && str[i] <= 'z') {
                    s[i] -= 0x20;
                }
            return s;
        }
        
        /// @brief 移除左侧的空格、换行符和制表符
        static string trimLeft(const string &str)
        {
            string::size_type index = str.find_first_not_of("\n\r\t");
            if (index != string::npos) {
                return str.substr(index);
            }
            return str;
        }

        /// @brief 移除右侧的空格、换行符和制表符
        static string trimRight(const string &str)
        {
            string::size_type index = str.find_last_not_of("\n\r\t");
            if (index != string::npos) {
                return str.substr(0, index + 1);
            }
            return str;
        }

        /// @brief 移除左右两侧的空格、换行符和制表符
        static string trim(const string &str)
        {
            return trimRight(trimLeft(str));
        }

        /// @brief 反转字符串
        static string reverse(const string &str)
        {
            string result;
            for (int i = (int)str.size() - 1; i >= 0; --i)
                result.append(1, str[i]);
            return result;
        }
    };

} // namespace rdpp

#endif // _RDPP_CORE_STRING_UTIL_H_