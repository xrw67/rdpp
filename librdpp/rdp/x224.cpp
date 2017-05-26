#include <rdp/x224.h>
#include <core/log.h>

#define TAG "X224"

using namespace rdpp;

namespace {

#include <core/pshpack1.h>

    /// @summary: Header send when x224 exchange application data
    struct X224DataHeader {
        uint8_t header;
        uint8_t messageType;
        uint8_t separator;

        X224DataHeader() : header(2), messageType(X224_TPDU_DATA), separator(0x80) {}
    };

    /// @summary: Negociate request message
    /// @see: request -> http://msdn.microsoft.com/en-us/library/cc240500.aspx
    /// @see: response -> http://msdn.microsoft.com/en-us/library/cc240506.aspx
    /// @see: failure ->http://msdn.microsoft.com/en-us/library/cc240507.aspx
    struct Negotiation {
        uint8_t code;
        uint8_t flag;
        const uint16_t len; // always 8
		union {
			uint32_t selectedProtocol; // if code != TYPE_RDP_NEG_FAILURE
			uint32_t failureCode; // if code == TYPE_RDP_NEG_FAILURE
		} d;

        Negotiation() : code(0), flag(0), len(8)
		{
			d.selectedProtocol = 0; 
		}
    };

    /// @summary:  Connection request
    ///             client -> server
    /// @see: http://msdn.microsoft.com/en-us/library/cc240470.aspx
    struct ClientConnectionRequestPDU {
        uint8_t len;
        uint8_t code;
        uint16_t padding1;
        uint16_t padding2;
        uint8_t padding3;
        string cookie;
        // read if there is enough data
        shared_ptr<Negotiation> protocolNeg;

        ClientConnectionRequestPDU() : len(0), code(X224_TPDU_CONNECTION_REQUEST)
            , padding1(0), padding2(0), padding3(0) {}

        void read(Buffer *data)
        {
            len = data->readUInt8();
            code = data->readUInt8();
            padding1 = data->readUInt16Be();
            padding2 = data->readUInt16Be();
            padding3 = data->readUInt8();

            if (data->length() > 14) { // Cookie: mstshash=IDENTIFIER
                const char *pos = (const char *)data->data();
                for (size_t i = 1; i < data->length(); ++i) {
                    if (pos[i - 1] == 0x0d && pos[i] == 0x0a)
                        cookie = data->retrieveAsString(i + 1);
                }
            }

            if (data->length() >= sizeof(Negotiation)) {
                protocolNeg = rdpp::make_shared<Negotiation>();
                data->retrieve(protocolNeg.get(), sizeof(Negotiation));
            }
        }

        void write(Buffer *data)
        {
            len = sizeof(code) + sizeof(padding1) + sizeof(padding2) + sizeof(padding3) + cookie.length();
            if (protocolNeg)
                len += sizeof(Negotiation);

            data->appendUInt8(len);
            data->appendUInt8(code);
            data->appendUInt16(padding1);
            data->appendUInt16(padding2);
            data->appendUInt8(padding3);
            data->append(cookie);
            data->append(protocolNeg.get(), sizeof(Negotiation));
        }
    };

    /// @summary: Server response
    /// @see: http://msdn.microsoft.com/en-us/library/cc240501.aspx
    struct ServerConnectionConfirm {
        uint8_t len;
        uint8_t code;
        uint16_t padding1;
        uint16_t padding2;
        uint8_t padding3;
        // read if there is enough data
        shared_ptr<Negotiation> protocolNeg;

        ServerConnectionConfirm() : len(0), code(X224_TPDU_CONNECTION_CONFIRM)
            , padding1(0), padding2(0), padding3(0) {}

        void read(Buffer *data)
        {
            len = data->readUInt8();
            code = data->readUInt8();
            padding1 = data->readUInt16Be();
            padding2 = data->readUInt16Be();
            padding3 = data->readUInt8();

            if (data->length() >= sizeof(Negotiation)) {
				protocolNeg = rdpp::make_shared<Negotiation>();
                data->retrieve(protocolNeg.get(), sizeof(Negotiation));
            }
        }

        void write(Buffer *data)
        {
            len = 6;
            if (protocolNeg)
                len += sizeof(Negotiation);

            data->appendUInt8(len);
            data->appendUInt8(code);
            data->appendUInt16(padding1);
            data->appendUInt16(padding2);
            data->appendUInt8(padding3);
            data->append(protocolNeg.get(), sizeof(Negotiation));
        }
    };
}

#include <core/poppack.h>

//
// X224Layer
//

X224Layer::X224Layer(Layer *presentation, RdpTransport *rdpTransport)
    : Layer(presentation)
	, _rdpTransport(rdpTransport)
    , _requestedProtocol(PROTOCOL_SSL | PROTOCOL_HYBRID) // client requested selectedProtocol
    , _selectedProtocol(PROTOCOL_SSL) // server selected selectedProtocol
{
}

void X224Layer::recvData(Buffer *data)
{
	X224DataHeader hdr;
    data->retrieve(&hdr, sizeof(X224DataHeader));
	assert(hdr.messageType == X224_TPDU_DATA);

    _presentation->recv(data);
}

void X224Layer::send(Buffer *data)
{
	X224DataHeader header;
    data->prepend(&header, sizeof(header));
    _transport->send(data);
}

//
// ClientX224Layer
//

ClientX224Layer::ClientX224Layer(Layer *presentation, RdpTransport *rdpTransport, NlaConnector *nlaConnector)
    : X224Layer(presentation, rdpTransport)
    , _nlaConnector(nlaConnector)
{
}

void ClientX224Layer::connect()
{
	RDPP_LOG(TAG, TRACE) << "ClientX224Layer::connect()";
    sendConnectionRequest();
}

void ClientX224Layer::sendConnectionRequest()
{
    Buffer s;
    ClientConnectionRequestPDU message;

    message.protocolNeg = rdpp::make_shared<Negotiation>();
    message.protocolNeg->code = TYPE_RDP_NEG_REQ;
    message.protocolNeg->d.selectedProtocol = _requestedProtocol;
    message.write(&s);

	RDPP_LOG(TAG, ERROR) << "ClientX224Layer::sendConnectionRequest(" << s.length() << " Bytes)";
    _transport->send(&s);
    setNextState(rdpp::bind(&ClientX224Layer::recvConnectionConfirm, this, _1));
}

void ClientX224Layer::recvConnectionConfirm(Buffer *data)
{
	RDPP_LOG(TAG, TRACE) << "ClientX224Layer::recvConnectionConfirm(" << data->length() << " Bytes)";

    ServerConnectionConfirm message;
    message.read(data);

	if ((message.protocolNeg != NULL) && (message.protocolNeg->code == TYPE_RDP_NEG_FAILURE)) {
		RDPP_LOG(TAG, ERROR) << "negotiation failure code: " << message.protocolNeg->d.failureCode;
        goto end;
    }

    // check presence of negotiation response
    if (message.protocolNeg != NULL)
        _selectedProtocol = message.protocolNeg->d.selectedProtocol;
    else
        _selectedProtocol = PROTOCOL_RDP;

    // NLA protocol doesn't support in actual version of RDPY
    if (_selectedProtocol & PROTOCOL_HYBRID_EX) {
        RDPP_LOG(TAG, ERROR) << "RDPY doesn't support PROTOCOL_HYBRID_EX security Layer";
        goto end;
    }

    // now i'm ready to receive data
    setNextState(rdpp::bind(&ClientX224Layer::recvData, this, _1));

    if (_selectedProtocol == PROTOCOL_RDP) {
        RDPP_LOG(TAG, INFO) << "*****************************************";
        RDPP_LOG(TAG, INFO) << "******* RDP Security selected ***********";
        RDPP_LOG(TAG, INFO) << "*****************************************";

        // connection is done send to presentation
        _presentation->connect();
    } else if (_selectedProtocol == PROTOCOL_SSL) {
        RDPP_LOG(TAG, INFO) << "*****************************************";
        RDPP_LOG(TAG, INFO) << "******* SSL Security selected ***********";
        RDPP_LOG(TAG, INFO) << "*****************************************";

		_rdpTransport->startTls();
        // connection is done send to presentation
        _presentation->connect();
    } else {
        RDPP_LOG(TAG, INFO) << "*****************************************";
        RDPP_LOG(TAG, INFO) << "******* NLA Security selected ***********";
        RDPP_LOG(TAG, INFO) << "*****************************************";

		_rdpTransport->startTls(); // start TLS first
        _nlaConnector->connectNla();
    }

	return;
end:
	close();
}

//
// ServerX224Layer
//

ServerX224Layer::ServerX224Layer(Layer *presentation, RdpTransport *rdpTransport)
    : X224Layer(presentation, rdpTransport)
{
}

void ServerX224Layer::connect()
{
	RDPP_LOG(TAG, TRACE) << "ServerX224Layer::connect()";
    setNextState(rdpp::bind(&ServerX224Layer::recvConnectionRequest, this, _1));
}

void ServerX224Layer::recvConnectionRequest(Buffer *data)
{
	RDPP_LOG(TAG, TRACE) << "ServerX224Layer::recvConnectionRequest(" << data->length() << " Bytes)";

    ClientConnectionRequestPDU message;
    message.read(data);

    if (message.protocolNeg == NULL)
        _requestedProtocol = PROTOCOL_RDP;
    else
        _requestedProtocol = message.protocolNeg->d.selectedProtocol;

    // match best security layer available
	if (_rdpTransport->isTlsSupport())
        _selectedProtocol = _requestedProtocol & PROTOCOL_SSL;
    else
        _selectedProtocol = _requestedProtocol & PROTOCOL_RDP;

    if (_selectedProtocol >= PROTOCOL_HYBRID) {
        RDPP_LOG(TAG, WARN) << "server reject client, because server support RDP and TLS only";
        // send error message and quit
		Buffer s;
        ServerConnectionConfirm confirm;
        confirm.protocolNeg = rdpp::make_shared<Negotiation>();
        confirm.protocolNeg->code = TYPE_RDP_NEG_FAILURE;
        confirm.protocolNeg->d.failureCode = SSL_REQUIRED_BY_SERVER;
        confirm.write(&s);
        _transport->send(&s);
        close();
        return;
    }

    sendConnectionConfirm();
}

void ServerX224Layer::sendConnectionConfirm()
{
    ServerConnectionConfirm message;
    message.protocolNeg = rdpp::make_shared<Negotiation>();

    message.protocolNeg->code = TYPE_RDP_NEG_RSP;
    message.protocolNeg->d.selectedProtocol = _selectedProtocol;
    
    Buffer s;
    message.write(&s);
	RDPP_LOG(TAG, TRACE) << "ServerX224Layer::sendConnectionConfirm(" << s.length() << " Bytes)";
    _transport->send(&s);

    if (_selectedProtocol == PROTOCOL_SSL) {
		RDPP_LOG(TAG, INFO) << "**************************************";
        RDPP_LOG(TAG, INFO) << "********** select SSL layer **********";
	    RDPP_LOG(TAG, INFO) << "**************************************";
        // _transport is TPKT and transport is TCP layy
		_rdpTransport->startTls();
    }

    // connection is done send to presentation
    setNextState(rdpp::bind(&ServerX224Layer::recvData, this, _1));
    _presentation->connect();
}
