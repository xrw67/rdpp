#include <core/timestamp.h>
#include <time.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/time.h>
#endif

using namespace rdpp;

string Timestamp::toFormatString()
{
	char buf[32] = {0};
	time_t seconds = static_cast<time_t>(_msTimestamp / kMilliSecondsPerSecond);
	int milliseconds = static_cast<int>(_msTimestamp % kMilliSecondsPerSecond);
	tm *tm_time = localtime(&seconds);

	snprintf(buf, sizeof(buf), "%4d%02d%02d %02d:%02d:%02d.%03d",
	tm_time->tm_year + 1900, tm_time->tm_mon + 1, tm_time->tm_mday,
	tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec,
	milliseconds);
	return buf;
}

Timestamp Timestamp::now()
{
#ifdef WIN32
    FILETIME ft;
    ULARGE_INTEGER ui;  
    GetSystemTimeAsFileTime(&ft); // ¾«È·µ½100ns
    ui.LowPart = ft.dwLowDateTime;  
    ui.HighPart = ft.dwHighDateTime;
    return Timestamp(static_cast<int64_t>(ui.QuadPart - 116444736000000000) / 10000);
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
    int64_t seconds = tv.tv_sec;
    return Timestamp(seconds * kMilliSecondsPerSecond + (tv.tv_usec / 1000));
#endif
}
