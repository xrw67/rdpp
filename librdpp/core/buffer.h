/** 
 * A buffer class modeled after org.jboss.netty.buffer.ChannelBuffer
 *
 * +-------------------+------------------+------------------+
 * | prependable bytes |  readable bytes  |  writable bytes  |
 * |                   |     (CONTENT)    |                  |
 * +-------------------+------------------+------------------+
 * |                   |                  |                  |
 * beginPtr   <=    readerPtr    <=    writerPtr    <=     endPtr
 */

#ifndef _RDPP_CORE_BUFFER_H_
#define _RDPP_CORE_BUFFER_H_

#include <core/config.h>
#include <stdlib.h>
#include <algorithm>
#include <vector>

namespace rdpp {

    class Buffer
    {
    public:
        static const size_t kCheapPrepend = 48;
        static const size_t kInitialSize = 1024;

        explicit Buffer(size_t initialSize = kInitialSize)
			: _buffer(kCheapPrepend + initialSize)
			, _readerIndex(kCheapPrepend)
			, _writerIndex(kCheapPrepend)
        {}

		void swap(Buffer &rhs)
		{
			_buffer.swap(rhs._buffer);
			std::swap(_readerIndex, rhs._readerIndex);
			std::swap(_writerIndex, rhs._writerIndex);
		}

        size_t length() const
		{ return _writerIndex - _readerIndex; }

        size_t writableBytes() const
		{ return _buffer.size() - _writerIndex; }

        size_t prependableBytes() const
		{ return _readerIndex; }

		uint8_t *data()
		{ return begin() + _readerIndex; }

		const uint8_t *data() const
		{ return begin() + _readerIndex; }

		char *c_str()
		{ return reinterpret_cast<char *>(data()); }

        void retrieve(size_t len)
        {
			assert(len <= length());

            if (len < length())
                _readerIndex += len;
            else
                clear();
        }

        void retrieveUntil(const uint8_t* end)
        {
            assert(data() <= end);
			assert(end <= beginWrite());
			retrieve(end - data());
        }

        void retrieveUInt64()
        { retrieve(sizeof(uint64_t)); }

        void retrieveUInt32()
        { retrieve(sizeof(uint32_t)); }

        void retrieveUInt16()
        { retrieve(sizeof(uint16_t)); }

        void retrieveUInt8()
        { retrieve(sizeof(uint8_t)); }

        void clear()
        {
			_readerIndex = kCheapPrepend;
			_writerIndex = kCheapPrepend;
        }

        string retrieveAllAsString()
        {
            return retrieveAsString(length());
        }

        string retrieveAsString(size_t len)
        {
			assert(len <= length());
			string result((const char *)data(), len);
			retrieve(len);
			return result;
        }
        void retrieve(void *to, size_t len)
        {
            memcpy(to, data(), len);
            retrieve(len);
        }
        void retrieve(Buffer &s, size_t len)
        {
            s.assign(data(), len);
            retrieve(len);
        }

        void append(size_t len, char c)
        {
            ensureWritableBytes(len);
            memset(beginWrite(), c, len);
            hasWritten(len);
        }

        void append(const uint8_t *data, size_t len)
        {
            ensureWritableBytes(len);
            std::copy(data, data + len, beginWrite());
            hasWritten(len);
        }

		void append(const void *data, size_t len)
		{ append(static_cast<const uint8_t *>(data), len); }

        void append(const string &s)
        { append(s.c_str(), s.length()); }

        void append(const Buffer &s)
        { append(s.data(), s.length()); }

		void append(const Buffer *s)
        { append(s->data(), s->length()); }

		void assign(const void *data, size_t len)
		{
			clear();
			append(data, len);
		}

		void assign(Buffer &rhs)
		{ assign(rhs.data(), rhs.length()); }

        uint8_t* beginWrite()
        { return begin() + _writerIndex; }

        const uint8_t* beginWrite() const
        { return begin() + _writerIndex; }

        void hasWritten(size_t len)
        { 
            assert(len <= writableBytes());
			_writerIndex += len;
        }

		void unwrite(size_t len)
		{
			assert(len <= length());
			_writerIndex -= len;
		}

		void resize(size_t len)
		{
			if (length() > len)
				_writerIndex = _readerIndex + len;
			else if (length() < len)
				append(len - length(), '\0');
		}

        void appendUInt64(uint64_t x)
        { append(&x, sizeof(x)); }

        void appendUInt32(uint32_t x)
        { append(&x, sizeof(x)); }

        void appendUInt32Be(uint32_t x);

        void appendUInt16(uint16_t x)
        { append(&x, sizeof(x)); }

        void appendUInt16Be(uint16_t x);

        void appendUInt8(uint8_t x)
        { append(&x, sizeof(x)); }

        uint64_t readUInt64()
        {
            uint64_t result = peekUInt64();
            retrieveUInt64();
            return result;
        }

        /// Require: buf->length() >= sizeof(uint32_t)
        uint32_t readUInt32()
        {
            uint32_t result = peekUInt32();
            retrieveUInt32();
            return result;
        }

        uint32_t readUInt32Be();

        uint16_t readUInt16()
        {
            uint16_t result = peekUInt16();
            retrieveUInt16();
            return result;
        }

        uint16_t readUInt16Be();

        uint8_t readUInt8()
        {
            uint8_t result = peekUInt8();
            retrieveUInt8();
            return result;
        }
        
        uint64_t peekUInt64() const
        {
			assert(length() >= sizeof(uint64_t));
            uint64_t x = 0;
            ::memcpy(&x, data(), sizeof(x));
            return x;
        }
        /// Require: buf->length() >= sizeof(uint32_t)
        uint32_t peekUInt32() const
        {
			assert(length() >= sizeof(uint32_t));
            uint32_t x = 0;
            ::memcpy(&x, data(), sizeof(x));
            return x;
        }
    
        uint32_t peekInt32Be() const;

        uint16_t peekUInt16() const
        {
			assert(length() >= sizeof(uint16_t));
            uint16_t x = 0;
            ::memcpy(&x, data(), sizeof(x));
            return x;
        }

        uint16_t peekInt16Be() const;

        uint8_t peekUInt8() const
        {
			assert(length() >= sizeof(uint8_t));
            uint8_t x = *data();
            return x;
        }

        void prependUInt64(uint64_t x)
        { prepend(&x, sizeof(x)); }

        void prependUInt32(uint32_t x)
        { prepend(&x, sizeof(x)); }

        void prependUInt32Be(uint32_t x);

        void prependUInt16(uint16_t x)
        { prepend(&x, sizeof(x)); }

        void prependUInt16Be(uint16_t x);

        void prependUInt8(uint8_t x)
        { prepend(&x, sizeof x); }

        void prepend(const void* data, size_t len)
        {
		    ensurePrependableBytes(len);
            _readerIndex -= len;
			const uint8_t *d = static_cast<const uint8_t *>(data);
			std::copy(d, d+len, begin() + _readerIndex);
        }

        void prepend(const string &data)
        {
            prepend(data.c_str(), data.length());
        }

		size_t internalCapacity() const
		{
			return _buffer.capacity();
		}
	
		void ensureWritableBytes(size_t len)
		{
			if (writableBytes() >= len)
				return;

			_buffer.resize(_writerIndex + len);
		}

        void ensurePrependableBytes(size_t len)
        {
			if (prependableBytes() >= len)
				return;

			len += kCheapPrepend;

			if (prependableBytes() + writableBytes() < len)
				_buffer.resize(_writerIndex + len);

			size_t readable = length();
			std::copy_backward(begin() + _readerIndex, 
				               begin() + _writerIndex,
							   begin() + readable + len);
			_readerIndex = len;
			_writerIndex = _readerIndex + readable;
			assert(readable == length());
        }

    private:
		uint8_t* begin()
		{ return &*_buffer.begin(); }

		const uint8_t* begin() const
		{ return &*_buffer.begin(); }

        std::vector<uint8_t> _buffer;
		size_t _readerIndex;
		size_t _writerIndex;
    };

	typedef shared_ptr<Buffer> BufferPtr;

} // namespace rdpp

#endif  // _RDPP_CORE_BUFFER_H_
