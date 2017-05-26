#include <core/buffer.h>

#ifdef WIN32
#pragma warning(disable:4996)
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define TAG "STREAM"

using namespace rdpp;

void Buffer::appendUInt32Be(uint32_t x)
{
    uint32_t be32 = htonl(x);
    append(&be32, sizeof(be32));
}

void Buffer::appendUInt16Be(uint16_t x)
{
    uint16_t be16 = htons(x);
    append(&be16, sizeof(be16));
}

uint32_t Buffer::readUInt32Be()
{
    uint32_t result = peekInt32Be();
    retrieveUInt32();
    return result;
}

uint16_t Buffer::readUInt16Be()
{
    uint16_t result = peekInt16Be();
    retrieveUInt16();
    return result;
}

uint32_t Buffer::peekInt32Be() const
{
	assert(length() >= sizeof(uint32_t));
    uint32_t be32 = 0;
    ::memcpy(&be32, data(), sizeof(be32));
    return ntohl(be32);
}

uint16_t Buffer::peekInt16Be() const
{
	assert(length() >= sizeof(uint16_t));
    uint16_t be16 = 0;
    ::memcpy(&be16, data(), sizeof(be16));
    return ntohs(be16);
}

void Buffer::prependUInt32Be(uint32_t x)
{
    uint32_t be32 = htonl(x);
    prepend(&be32, sizeof(be32));
}

void Buffer::prependUInt16Be(uint16_t x)
{
    uint16_t be16 = htons(x);
    prepend(&be16, sizeof(be16));
}
