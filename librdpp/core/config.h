#ifndef _RDPP_CORE_CONFIG_H_
#define _RDPP_CORE_CONFIG_H_

// Config
#define RDPP_VERSION "1.0.0.1024"

// 是否使用C++11，否则要使用boost
#define RDPP_USE_CXX11

#ifdef WIN32
#pragma warning(disable:4819)
#pragma warning(disable:4996)
#define snprintf _snprintf
#endif

#include <string>
#include <stdint.h>
#include <assert.h>

#ifdef RDPP_USE_CXX11
	#include <memory>
	#include <functional>
#else
	#include <boost/shared_ptr.hpp>
	#include <boost/make_shared.hpp>
	#include <boost/function.hpp>
	#include <boost/bind.hpp>
#endif

namespace rdpp {


#ifdef RDPP_USE_CXX11
    using std::shared_ptr;
    using std::make_shared;
    using std::function;
    using std::bind;
	using std::placeholders::_1;
	using std::placeholders::_2;
	using std::placeholders::_3;
	using std::placeholders::_4;
	using std::placeholders::_5;
	using std::placeholders::_6;
#else
    using boost::shared_ptr;
    using boost::make_shared;
    using boost::function;
    using boost::bind;
#endif

    using std::string;

	// disallow copy ctor and assign opt
    #undef RDPP_DISALLOW_EVIL_CONSTRUCTORS
    #define RDPP_DISALLOW_EVIL_CONSTRUCTORS(TypeName)    \
        TypeName(const TypeName&);                       \
        void operator=(const TypeName&)

	#define MIN(a,b) ((a)<(b)) ? (a) : (b)
	#define MAX(a,b) ((a)>(b)) ? (a) : (b)

} // namespace rdpp

#endif // _RDPP_CORE_CONFIG_H_
