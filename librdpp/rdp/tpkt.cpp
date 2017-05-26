#include <rdp/tpkt.h>
#include <core/log.h>

#define TAG "TPKT"

using namespace rdpp;

TPKTLayer::TPKTLayer(Layer *presentation, FastPathLayer *fastPathListener, 
                     RdpTransport *rdpTransport)
	: Layer(presentation)
    , FastPathLayer(fastPathListener)
	, _rdpTransport(rdpTransport)
    , _lastShortLength(0)
    , _secFlag(0)
{
}

void TPKTLayer::connect()
{
	RDPP_LOG(TAG, TRACE) << "TPKTLayer::connect";

	// header is on two bytes
	expect(2, rdpp::bind(&TPKTLayer::readHeader, this, _1));
	// no connection automata on this layer
	if (_presentation != NULL)
		_presentation->connect();
}

void TPKTLayer::close()
{
	_rdpTransport->transportClose();
}

void TPKTLayer::dataReceived(Buffer *data)
{
    while (true) {
        const size_t readableBytes = data->length();
        
		if (readableBytes < _expectedLen)
			return;

		const size_t expectedLen = _expectedLen;
        Buffer packet;

		packet.append(data->data(), expectedLen);
        recv(&packet);
        data->retrieve(expectedLen);
    }
}

void TPKTLayer::readHeader(Buffer *data)
{
	// first read packet version
	uint8_t version = data->readUInt8();
	// classic packet
	if (FASTPATH_ACTION_X224 == version) {
		// padding
		data->readUInt8();
		// read end header
		expect(2, rdpp::bind(&TPKTLayer::readExtendedHeader, this, _1));
	} else {
		// is fast path packet
		_secFlag = (version >> 6) & 0x03;
		_lastShortLength = data->readUInt8();
		if (_lastShortLength & 0x80)
			expect(1, rdpp::bind(&TPKTLayer::readExtendedFastPathHeader, this, _1)); // size is 1 byte more
        else
		    expect(_lastShortLength - 2, rdpp::bind(&TPKTLayer::readFastPath, this, _1));
	}
}

void TPKTLayer::readExtendedHeader(Buffer *data)
{
	// next state is read data
	uint16_t size = data->readUInt16Be();
	expect(size - 4, rdpp::bind(&TPKTLayer::readData, this, _1));
}

void TPKTLayer::readExtendedFastPathHeader(Buffer *data)
{
	uint8_t leftPart = data->readUInt8();
	_lastShortLength &= ~0x80;
	uint16_t packetSize = (_lastShortLength << 8) + leftPart;
	// next state is fast patn data
	expect(packetSize - 3, rdpp::bind(&TPKTLayer::readFastPath, this, _1));
}

void TPKTLayer::readFastPath(Buffer *data)
{
	RDPP_LOG(TAG, TRACE) << "TPKTLayer::readFastPath()";

    _fastPathListener->recvFastPath(_secFlag, data);
    expect(2, rdpp::bind(&TPKTLayer::readHeader, this, _1));
}

void TPKTLayer::readData(Buffer *data)
{
	RDPP_LOG(TAG, TRACE) << "TPKTLayer::readData()";
    _presentation->recv(data);
	// next packet
	expect(2, rdpp::bind(&TPKTLayer::readHeader, this, _1));
}

void TPKTLayer::send(Buffer *data)
{
    RDPP_LOG(TAG, TRACE) << "TPKTLayer::send()";

	data->prependUInt16Be(data->length() + 4);
	data->prependUInt8(0);
	data->prependUInt8(FASTPATH_ACTION_X224);
	_rdpTransport->transportSend(data);
}

void TPKTLayer::sendFastPath(uint16_t secFlag, Buffer *data)
{
    data->prependUInt16Be((data->length() + 3) | 0x8000);
    data->prependUInt8(FASTPATH_ACTION_FASTPATH | ((secFlag & 0x03) << 6));

    RDPP_LOG(TAG, TRACE) << "TPKTLayer::sendFastPath()";
	_rdpTransport->transportSend(data);
}

void TPKTLayer::expect(size_t expectedLen, const Layer::OnRecvCallback &callback)
{
    _expectedLen = expectedLen;
    setNextState(callback);
}
