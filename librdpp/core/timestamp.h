/**
 * 时间戳，精确到1毫妙,格式：20131001 08:30:00.000
 */

#ifndef _RDPP_CORE_TIMESTAMP_H_
#define _RDPP_CORE_TIMESTAMP_H_

#include <core/config.h>

namespace rdpp {

    class Timestamp
    {
    public:
        Timestamp()
            : _msTimestamp(0)
        {}
        Timestamp(int64_t msTimestamp)
            : _msTimestamp(msTimestamp)
        {}
        Timestamp(const Timestamp &ts)
            : _msTimestamp(ts._msTimestamp)
        {}

		string toFormatString();

        uint64_t timestamp() const { return _msTimestamp; }

        bool valid() const { return _msTimestamp > 0; }


        static Timestamp now();
        static Timestamp invalid() { return Timestamp(); }

        static const int kMilliSecondsPerSecond = 1000;

    private:
        uint64_t _msTimestamp;
    };

} // namespace rdpp

#endif // _RDPP_CORE_TIMESTAMP_H_
