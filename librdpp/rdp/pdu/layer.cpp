#include <rdp/pdu/layer.h>
#include <rdp/sec.h>
#include <rdp/t125/mcs.h>
#include <rdp/pdu/data.h>
#include <rdp/pdu/order.h>

#define TAG "PDU"

using namespace rdpp;

//
// PDULayer
//
PDULayer::PDULayer()
    : _shareId(0x103ea) // share id between client and server
{
}

void PDULayer::sendPDU(uint16_t pduType, Buffer *pduMessage)
{
    ShareControlHeader hdr;
    hdr.pduType = pduType;
    hdr.totalLength = sizeof(hdr) + pduMessage->length();
    hdr.PDUSource = transport()->getUserId();

    pduMessage->prepend(&hdr, sizeof(hdr));
    transport()->send(pduMessage);
}

void PDULayer::sendDataPDU(uint8_t pduType2, Buffer *pduData)
{
    ShareDataHeader hdr;

    memset(&hdr, 0, sizeof(hdr));
    hdr.pduType2 = pduType2;
    hdr.shareId = _shareId;
    hdr.streamId = STREAM_LOW;
    hdr.uncompressedLength = sizeof(hdr) + pduData->length() - 8;

    pduData->prepend(&hdr, sizeof(hdr));
    sendPDU(PDUTYPE_DATAPDU, pduData);
}

SecLayer *PDULayer::transport()
{
    return dynamic_cast<SecLayer *>(_transport);
}

//
// ClientPDULayer
//
ClientPDULayer::ClientPDULayer(PduClientListener *listener)
    : _listener(listener)
{
}

void ClientPDULayer::connect()
{
    _gccCore = &(transport()->getGCCClientSettings().core);
    setNextState(rdpp::bind(&ClientPDULayer::recvDemandActivePDU, this, _1));
    // check if client support fast path message
    _clientFastPathSupported = false;
}

void ClientPDULayer::close()
{
    transport()->close();
}

void ClientPDULayer::recvDemandActivePDU(Buffer *s)
{
	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::recvDemandActivePDU(" << s->length() << " Bytes)";

    ShareControlHeader hdr;
    hdr.read(s);

    if (hdr.pduType != PDUTYPE_DEMANDACTIVEPDU) {
        // not a blocking error because in deactive reactive sequence
        // input can be send too but ignored
        RDPP_LOG(TAG, DEBUG) << "Ignore message type " << (void *)hdr.pduType << " during connection sequence";
        return;
    }

    DemandActivePDU msg;
    msg.read(s);

	_shareId = msg.shareId;

    for (size_t i = 0; i < msg.numberCapabilities; ++i) {
        Capability hdr;
        memcpy(&hdr, msg.capabilitySets.data(), sizeof(hdr));
        _serverCaps.read(msg.capabilitySets.retrieveAsString(hdr.lengthCapability));
    }

    // secure checksum cap here maybe protocol (another) design error
    transport()->_enableSecureCheckSum = (_serverCaps.general.extraFlags & ENC_SALTED_CHECKSUM) ? true : false;

    sendConfirmActivePDU();
    // send synchronize
    sendClientFinalizeSynchronizePDU();
    setNextState(rdpp::bind(&ClientPDULayer::recvServerSynchronizePDU, this, _1));
}

void ClientPDULayer::recvServerSynchronizePDU(Buffer *s)
{
	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::recvServerSynchronizePDU(" << s->length() << " Bytes)";

    ShareControlHeader hdr;
    hdr.read(s);
    if (hdr.pduType != PDUTYPE_DATAPDU) {
        RDPP_LOG(TAG, DEBUG) << "Ignore message type " << (void *)hdr.pduType << " during connection sequence";
        return;
    }

    ShareDataHeader dataHdr;
    dataHdr.read(s);
    if (dataHdr.pduType2 != PDUTYPE2_SYNCHRONIZE) {
        RDPP_LOG(TAG, DEBUG) << "Ignore data type " << (void *)dataHdr.pduType2 << " during connection sequence";
        return;
    }

    setNextState(rdpp::bind(&ClientPDULayer::recvServerControlCooperatePDU, this, _1));
}

void ClientPDULayer::recvServerControlCooperatePDU(Buffer *s)
{
	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::recvServerControlCooperatePDU(" << s->length() << " Bytes)";

    ShareControlHeader hdr;
    hdr.read(s);
    if (hdr.pduType != PDUTYPE_DATAPDU) {
        RDPP_LOG(TAG, DEBUG) << "Ignore message type " << (void *)hdr.pduType << " during connection sequence";
        return;
    }

    ShareDataHeader dataHdr;
    dataHdr.read(s);
    if (dataHdr.pduType2 != PDUTYPE2_CONTROL) {
        RDPP_LOG(TAG, DEBUG) << "Ignore data type " << (void *)dataHdr.pduType2 << " during connection sequence";
        return;
    }

    ControlDataPDU msg;
    s->retrieve(&msg, sizeof(ControlDataPDU));
    if (msg.action != CTRLACTION_COOPERATE) {
        RDPP_LOG(TAG, DEBUG) << "ControlDataPDU.action != CTRLACTION_COOPERATE";
        return;
    }

    setNextState(rdpp::bind(&ClientPDULayer::recvServerControlGrantedPDU, this, _1));
}

void ClientPDULayer::recvServerControlGrantedPDU(Buffer *s)
{
	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::recvServerControlGrantedPDU(" << s->length() << " Bytes)";

    ShareControlHeader hdr;
    hdr.read(s);
    if (hdr.pduType != PDUTYPE_DATAPDU) {
        RDPP_LOG(TAG, DEBUG) << "Ignore message type " << (void *)hdr.pduType << " during connection sequence";
        return;
    }

    ShareDataHeader dataHdr;
    dataHdr.read(s);
    if (dataHdr.pduType2 != PDUTYPE2_CONTROL) {
        RDPP_LOG(TAG, DEBUG) << "Ignore data type " << (void *)dataHdr.pduType2 << " during connection sequence";
        return;
    }

    ControlDataPDU msg;
	s->retrieve(&msg, sizeof(ControlDataPDU));
    if (msg.action != CTRLACTION_GRANTED_CONTROL) {
        RDPP_LOG(TAG, DEBUG) << "ControlDataPDU.action != CTRLACTION_GRANTED_CONTROL";
        return;
    }

    setNextState(rdpp::bind(&ClientPDULayer::recvServerFontMapPDU, this, _1));
}

void ClientPDULayer::recvServerFontMapPDU(Buffer *s)
{
	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::recvServerFontMapPDU(" << s->length() << " Bytes)";

    ShareControlHeader hdr;
    hdr.read(s);
    if (hdr.pduType != PDUTYPE_DATAPDU) {
        RDPP_LOG(TAG, DEBUG) << "Ignore message type " << (void *)hdr.pduType << " during connection sequence";
        return;
    }

    ShareDataHeader dataHdr;
    dataHdr.read(s);
    if (dataHdr.pduType2 != PDUTYPE2_FONTMAP) {
        RDPP_LOG(TAG, DEBUG) << "Ignore data type " << (void *)dataHdr.pduType2 << " during connection sequence";
        return;
    }
    setNextState(rdpp::bind(&ClientPDULayer::recvPDU, this, _1));
	// here i'm connected
    _listener->onReady();
}

void ClientPDULayer::recvPDU(Buffer *s)
{
    ShareControlHeader hdr;

    while (s->length() >= hdr.minSize()) {
        hdr.read(s);
		RDPP_LOG(TAG, TRACE) << "ClientPDULayer::recvPDU(pduType:" << (void *)hdr.pduType << ", len:" << hdr.totalLength << " Bytes)";
        if (hdr.pduType == PDUTYPE_DATAPDU) {
            readDataPDU(s, hdr.totalLength - sizeof(hdr));
        } else if (hdr.pduType == PDUTYPE_DEACTIVATEALLPDU) {
            // use in deactivation - reactivation sequence
            // next state is either a capabilities re exchange or disconnection
            // http://msdn.microsoft.com/en-us/library/cc240454.aspx
            setNextState(rdpp::bind(&ClientPDULayer::recvDemandActivePDU, this, _1));
        }
    }
}

void ClientPDULayer::recvFastPath(uint16_t secFlag, Buffer *fastPathS)
{
    FastPathUpdatePDU hdr;

    while (fastPathS->length() >= sizeof(hdr)) {
        hdr.read(fastPathS);
        switch (hdr.type()) {
		case FASTPATH_UPDATETYPE_BITMAP:
		{
            FastPathBitmapUpdateDataPDU data;
			RDPP_LOG(TAG, DEBUG) << "ClientPDULayer::recvFastpath(FASTPATH_UPDATETYPE_BITMAP, len:" << hdr.size << " Bytes)";
            data.read(fastPathS);
			_listener->onUpdate(data.rectangles);
			break;
        }
		case FASTPATH_UPDATETYPE_SYNCHRONIZE:
			fastPathS->retrieve(hdr.size);
			RDPP_LOG(TAG, DEBUG) << "ClientPDULayer::recvFastpath(FASTPATH_UPDATETYPE_SYNCHRONIZE, len:" << hdr.size << " Bytes)";
			break;
		case FASTPATH_UPDATETYPE_COLOR:
			fastPathS->retrieve(hdr.size);
			RDPP_LOG(TAG, DEBUG) << "ClientPDULayer::recvFastpath(FASTPATH_UPDATETYPE_COLOR, len:" << hdr.size << " Bytes)";
			break;
		case FASTPATH_UPDATETYPE_CACHED:
			fastPathS->retrieve(hdr.size);
			RDPP_LOG(TAG, DEBUG) << "ClientPDULayer::recvFastpath(FASTPATH_UPDATETYPE_CACHED, len:" << hdr.size << " Bytes)";
			break;
		default:
            fastPathS->retrieve(hdr.size);
			RDPP_LOG(TAG, DEBUG) << "unimpl FastPathUpdatePDU, type=" << (void *)hdr.type();
			break;
        }
    }
}

void ClientPDULayer::readDataPDU(Buffer *s, uint16_t readLen)
{
    ShareDataHeader dataHdr;
    dataHdr.read(s);
	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::readDataPDU(pduType2:" << (void *)dataHdr.pduType2 << ")";

    if (dataHdr.pduType2 == PDUTYPE2_SET_ERROR_INFO_PDU) {
        // ignore 0 error code because is not an error code
        ErrorInfoDataPDU data;
        s->retrieve(&data, sizeof(data));

        if (data.errorInfo == 0)
            return;
        RDPP_LOG(TAG, INFO) << "PDU : " << errorMessage(data.errorInfo);
    } else if (dataHdr.pduType2 == PDUTYPE2_SHUTDOWN_DENIED) {
        // may be an event to ask to user
        transport()->close();
    } else if (dataHdr.pduType2 == PDUTYPE2_SAVE_SESSION_INFO) {
        SaveSessionInfoPDU data;
        data.read(s, readLen - sizeof(dataHdr));
        // handle session event
		_listener->onSessionReady();
    } else if (dataHdr.pduType2 == PDUTYPE2_UPDATE) {
        readUpdateDataPDU(s, readLen - sizeof(dataHdr));
    }
}

void ClientPDULayer::readUpdateDataPDU(Buffer *s, uint16_t readLen)
{
    UpdateDataPDU hdr;
    s->retrieve(&hdr, sizeof(hdr));
	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::readUpdateDataPDU(updateType:" << (void *)hdr.updateType << ")";

    if (hdr.updateType == UPDATETYPE_BITMAP) {
        BitmapUpdateDataPDU data;
        data.read(s);
		_listener->onUpdate(data.rectangles);
    } else {
        s->retrieve(readLen - sizeof(hdr));
        RDPP_LOG(TAG, DEBUG) << "unknown PDU data type" << (void *)hdr.updateType;
    }
}

void ClientPDULayer::sendConfirmActivePDU()
{
    // init general capability
    _clientCaps.general.osMajorType = OSMAJORTYPE_WINDOWS;
    _clientCaps.general.osMinorType = OSMINORTYPE_WINDOWS_NT;
    _clientCaps.general.extraFlags = LONG_CREDENTIALS_SUPPORTED | NO_BITMAP_COMPRESSION_HDR | ENC_SALTED_CHECKSUM;
    _clientCaps.general.extraFlags = LONG_CREDENTIALS_SUPPORTED | NO_BITMAP_COMPRESSION_HDR | ENC_SALTED_CHECKSUM;
    if (_fastPathSender)
        _clientCaps.general.extraFlags |= FASTPATH_OUTPUT_SUPPORTED;

    // init bitmap capability
    _clientCaps.bitmap.preferredBitsPerPixel = _gccCore->highColorDepth;
    _clientCaps.bitmap.desktopWidth = _gccCore->desktopWidth;
    _clientCaps.bitmap.desktopHeight = _gccCore->desktopHeight;

    // init order capability
    _clientCaps.order.orderFlags |= ZEROBOUNDSDELTASSUPPORT;

    // init input capability
    _clientCaps.input.inputFlags= INPUT_FLAG_SCANCODES | INPUT_FLAG_MOUSEX | INPUT_FLAG_UNICODE;
    _clientCaps.input.keyboardLayout = _gccCore->kbdLayout;
    _clientCaps.input.keyboardType = _gccCore->keyboardType;
    _clientCaps.input.keyboardSubType = _gccCore->keyboardSubType;
    _clientCaps.input.keyboardFunctionKey = _gccCore->keyboardFnKeys;
    memcpy(&_clientCaps.input.imeFileName, _gccCore->imeFileName, 64);

    // make active PDU packet
    ConfirmActivePDU msg;
    msg.shareId = _shareId;

    msg.capabilitySets.append(&_clientCaps, sizeof(_clientCaps));
    msg.numberCapabilities = 12;
    msg.lengthCombinedCapabilities = msg.capabilitySets.length() + sizeof(msg.numberCapabilities) + sizeof(msg.pad2Octets);
    
    Buffer pduMessage;
    msg.write(&pduMessage);

	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::sendConfirmActivePDU(" << pduMessage.length() << " Bytes) " << hexdump(pduMessage);
    sendPDU(PDUTYPE_CONFIRMACTIVEPDU, &pduMessage);
}

void ClientPDULayer::sendClientFinalizeSynchronizePDU()
{
    Buffer s;

    SynchronizeDataPDU sync(transport()->getChannelId());
	s.assign(&sync, sizeof(sync));
	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::sendClientFinalizeSynchronizePDU(SynchronizeDataPDU, " << s.length() << " Bytes)";
    sendDataPDU(PDUTYPE2_SYNCHRONIZE, &s);

    // ask for cooperation
    ControlDataPDU cooperation(CTRLACTION_COOPERATE);
    s.assign(&cooperation, sizeof(cooperation));
	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::sendClientFinalizeSynchronizePDU(ControlDataPDU, " << s.length() << " Bytes)";
    sendDataPDU(PDUTYPE2_CONTROL, &s);

    // request control
    ControlDataPDU request(CTRLACTION_REQUEST_CONTROL);
    s.assign(&request, sizeof(request));
	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::sendClientFinalizeSynchronizePDU(ControlDataPDU, " << s.length() << " Bytes)";
    sendDataPDU(PDUTYPE2_CONTROL, &s);

    // TODO persistent key list http://msdn.microsoft.com/en-us/library/cc240494.aspx

    // deprecated font list pdu
    FontListDataPDU fontlist;
    s.assign(&fontlist, sizeof(fontlist));
	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::sendClientFinalizeSynchronizePDU(FontListDataPDU, " << s.length() << " Bytes)";
    sendDataPDU(PDUTYPE2_FONTLIST, &s);
}

void ClientPDULayer::sendInputEvents(uint16_t eventType, uint16_t numEvents, Buffer *slowPathInputEvents)
{
    SlowPathInputEvent ev;
    ev.eventTime = 0;
    ev.messageType = eventType;
    slowPathInputEvents->prepend(&ev, sizeof(ev));

    ClientInputEventPDU hdr(numEvents);
    slowPathInputEvents->prepend(&hdr, sizeof(hdr));
	RDPP_LOG(TAG, TRACE) << "ClientPDULayer::sendInputEvents(eventType:" << (void *)eventType << ", numEvents:" << numEvents << ", "<< slowPathInputEvents->length() << " Bytes)";
    sendDataPDU(PDUTYPE2_INPUT, slowPathInputEvents);
}

//
// ServerPDULayer
//

ServerPDULayer::ServerPDULayer(PduServerListener *listener)
    : _listener(listener)
{
}

void ServerPDULayer::connect()
{
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::connect()";

    sendDemandActivePDU();
    setNextState(rdpp::bind(&ServerPDULayer::recvConfirmActivePDU, this, _1));
}

void ServerPDULayer::recvConfirmActivePDU(Buffer *s)
{
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::recvConfirmActivePDU(" << s->length() << " Bytes)";

    ShareControlHeader hdr;
    hdr.read(s);
    if (hdr.pduType != PDUTYPE_CONFIRMACTIVEPDU) {
        RDPP_LOG(TAG, DEBUG) << "Ignore message type " << (void *)hdr.pduType << " during connection sequence";
        return;
    }

    ConfirmActivePDU msg;
    msg.read(s);

    for (size_t i = 0; i < msg.numberCapabilities; ++i) {
        Capability hdr;
        memcpy(&hdr, msg.capabilitySets.data(), sizeof(hdr));
        _clientCaps.read(msg.capabilitySets.retrieveAsString(hdr.lengthCapability));
    }

    // find use full flag
    _clientFastPathSupported = _clientCaps.general.extraFlags & FASTPATH_OUTPUT_SUPPORTED;

    // secure checksum cap here maybe protocol (another) design error
    transport()->_enableSecureCheckSum = (_clientCaps.general.extraFlags & ENC_SALTED_CHECKSUM) ? true : false;

    setNextState(rdpp::bind(&ServerPDULayer::recvClientSynchronizePDU, this, _1));
}

void ServerPDULayer::recvClientSynchronizePDU(Buffer *s)
{
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::recvClientSynchronizePDU(" << s->length() << " Bytes)";

    ShareControlHeader hdr;
    hdr.read(s);
    if (hdr.pduType != PDUTYPE_DATAPDU) {
        RDPP_LOG(TAG, DEBUG) << "Ignore message type " << (void *)hdr.pduType << " during connection sequence";
        return;
    }

    ShareDataHeader dataHdr;
    dataHdr.read(s);
    if (dataHdr.pduType2 != PDUTYPE2_SYNCHRONIZE) {
        RDPP_LOG(TAG, DEBUG) << "Ignore data type " << (void *)dataHdr.pduType2 << " during connection sequence";
        return;
    }

    setNextState(rdpp::bind(&ServerPDULayer::recvClientControlCooperatePDU, this, _1));
}

void ServerPDULayer::recvClientControlCooperatePDU(Buffer *s)
{
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::recvClientControlCooperatePDU(" << s->length() << " Bytes)";

    ShareControlHeader hdr;
    hdr.read(s);
    if (hdr.pduType != PDUTYPE_DATAPDU) {
        RDPP_LOG(TAG, DEBUG) << "Ignore message type " << (void *)hdr.pduType << " during connection sequence";
        return;
    }

    ShareDataHeader dataHdr;
    dataHdr.read(s);
    if (dataHdr.pduType2 != PDUTYPE2_CONTROL) {
        RDPP_LOG(TAG, DEBUG) << "Ignore data type " << (void *)dataHdr.pduType2 << " during connection sequence";
        return;
    }

    ControlDataPDU msg;
    s->retrieve(&msg, sizeof(ControlDataPDU));
    if (msg.action != CTRLACTION_COOPERATE) {
        RDPP_LOG(TAG, DEBUG) << "ControlDataPDU.action != CTRLACTION_COOPERATE";
        return;
    }

    setNextState(rdpp::bind(&ServerPDULayer::recvClientControlRequestPDU, this, _1));
}

void ServerPDULayer::recvClientControlRequestPDU(Buffer *s)
{
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::recvClientControlRequestPDU(" << s->length() << " Bytes)";

    ShareControlHeader hdr;
    hdr.read(s);
    if (hdr.pduType != PDUTYPE_DATAPDU) {
        RDPP_LOG(TAG, DEBUG) << "Ignore message type " << (void *)hdr.pduType << " during connection sequence";
        return;
    }

    ShareDataHeader dataHdr;
    dataHdr.read(s);
    if (dataHdr.pduType2 != PDUTYPE2_CONTROL) {
        RDPP_LOG(TAG, DEBUG) << "Ignore data type " << (void *)dataHdr.pduType2 << " during connection sequence";
        return;
    }

    ControlDataPDU msg;
    s->retrieve(&msg, sizeof(ControlDataPDU));
    if (msg.action != CTRLACTION_REQUEST_CONTROL) {
        RDPP_LOG(TAG, DEBUG) << "ControlDataPDU.action != CTRLACTION_COOPERATE";
        return;
    }

    setNextState(rdpp::bind(&ServerPDULayer::recvClientFontListPDU, this, _1));
}

void ServerPDULayer::recvClientFontListPDU(Buffer *s)
{
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::recvClientFontListPDU(" << s->length() << " Bytes)";

    ShareControlHeader hdr;
    hdr.read(s);
    if (hdr.pduType != PDUTYPE_DATAPDU) {
        RDPP_LOG(TAG, DEBUG) << "Ignore message type " << (void *)hdr.pduType << " during connection sequence";
        return;
    }

    ShareDataHeader dataHdr;
    dataHdr.read(s);
    if (dataHdr.pduType2 != PDUTYPE2_FONTLIST) {
        RDPP_LOG(TAG, DEBUG) << "Ignore data type " << (void *)dataHdr.pduType2 << " during connection sequence";
        return;
    }

    sendServerFinalizeSynchronizePDU();
    setNextState(rdpp::bind(&ServerPDULayer::recvPDU, this, _1));
	// now i'm ready
	_listener->onReady();
}

void ServerPDULayer::recvPDU(Buffer *s)
{
    ShareControlHeader hdr;
    hdr.read(s);
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::recvPDU(pduType:" << (void *)hdr.pduType << ", len:" << hdr.totalLength << ")";

    if (PDUTYPE_DATAPDU == hdr.pduType) {
        readDataPDU(s, hdr.totalLength - sizeof(hdr));
    }    
}

void ServerPDULayer::readDataPDU(Buffer *s, uint16_t readLen)
{
    ShareDataHeader dataHdr;
    dataHdr.read(s);
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::readDataPDU(pduType2:" << (void *)dataHdr.pduType2 << ")";

    if (dataHdr.pduType2 == PDUTYPE2_SET_ERROR_INFO_PDU) {
        ErrorInfoDataPDU data;
        s->retrieve(&data, sizeof(data));
        RDPP_LOG(TAG, INFO) << "PDU : " << errorMessage(data.errorInfo);
    } else if (dataHdr.pduType2 == PDUTYPE2_INPUT) {
		ClientInputEventPDU data;
		s->retrieve(&data, sizeof(data));
		_listener->onSlowPathInput(data.numEvents, s);
    } else if (dataHdr.pduType2 == PDUTYPE2_SHUTDOWN_REQUEST) {
        RDPP_LOG(TAG, INFO) << "Receive Shutdown Request";
        transport()->close();
    }
}

void ServerPDULayer::recvFastPath(uint16_t secFlag, Buffer *fastPathS)
{
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::recvFastPath(" << fastPathS->length() << " Bytes)";
    return;
}

void ServerPDULayer::sendDemandActivePDU()
{
    // init general capability
    _serverCaps.general.osMajorType = OSMAJORTYPE_WINDOWS;
    _serverCaps.general.osMinorType = OSMINORTYPE_WINDOWS_NT;
    _serverCaps.general.extraFlags = LONG_CREDENTIALS_SUPPORTED | NO_BITMAP_COMPRESSION_HDR |  FASTPATH_OUTPUT_SUPPORTED | ENC_SALTED_CHECKSUM;
    _serverCaps.input.inputFlags = INPUT_FLAG_SCANCODES | INPUT_FLAG_MOUSEX;

    DemandActivePDU msg(_shareId);

    msg.capabilitySets.append(&_serverCaps, sizeof(_serverCaps));
    msg.numberCapabilities = 9;
    msg.lengthCombinedCapabilities = msg.capabilitySets.length() + sizeof(msg.numberCapabilities) + sizeof(msg.pad2Octets);
    
    Buffer pduMessage;
    msg.write(&pduMessage);

	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::sendDemandActivePDU(" << pduMessage.length() << " Bytes)";
    sendPDU(PDUTYPE_DEMANDACTIVEPDU, &pduMessage);
}

void ServerPDULayer::sendServerFinalizeSynchronizePDU()
{
    Buffer s;

    SynchronizeDataPDU sync(transport()->getChannelId());
    s.assign(&sync, sizeof(sync));
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::sendServerFinalizeSynchronizePDU(SynchronizeDataPDU, " << s.length() << " Bytes)";
    sendDataPDU(PDUTYPE2_SYNCHRONIZE, &s);

    // ask for cooperation
    ControlDataPDU cooperation(CTRLACTION_COOPERATE);
    s.assign(&cooperation, sizeof(cooperation));
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::sendServerFinalizeSynchronizePDU(ControlDataPDU, " << s.length() << " Bytes)";
    sendDataPDU(PDUTYPE2_CONTROL, &s);

    // request control
    ControlDataPDU request(CTRLACTION_GRANTED_CONTROL);
    s.assign(&request, sizeof(request));
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::sendServerFinalizeSynchronizePDU(ControlDataPDU, " << s.length() << " Bytes)";
    sendDataPDU(PDUTYPE2_CONTROL, &s);

    // TODO persistent key list http://msdn.microsoft.com/en-us/library/cc240494.aspx

    // deprecated font list pdu
    FontMapDataPDU fontMap;
    s.assign(&fontMap, sizeof(fontMap));
	RDPP_LOG(TAG, TRACE) << "ServerPDULayer::sendServerFinalizeSynchronizePDU(FontMapDataPDU, " << s.length() << " Bytes)";
    sendDataPDU(PDUTYPE2_FONTMAP, &s);
}

void ServerPDULayer::sendPDU(uint16_t pduType, Buffer *pduMessage)
{
    PDULayer::sendPDU(pduType, pduMessage);
    // restart capabilities exchange in case of deactive reactive sequence
    if (pduType == PDUTYPE_DEACTIVATEALLPDU) {
        sendDemandActivePDU();
        setNextState(rdpp::bind(&ServerPDULayer::recvConfirmActivePDU, this, _1));
    }
}

void ServerPDULayer::sendBitmapUpdatePDU(std::vector<BitmapDataPtr> &bitmapDatas)
{
    // check bitmap header for client that want it(very old client)
    if (_clientCaps.general.extraFlags & NO_BITMAP_COMPRESSION_HDR) {
        for (size_t i = 0; i < bitmapDatas.size(); ++i) {
            if (bitmapDatas[i]->flags & BITMAP_COMPRESSION)
                bitmapDatas[i]->flags |= BITMAP_NO_COMPRESSION_HDR;
        }
    }

    if (_clientFastPathSupported && _fastPathSender) {
        // fast path case
        FastPathBitmapUpdateDataPDU data;
        data.rectangles = bitmapDatas;
		data.numberRectangles = bitmapDatas.size();

        Buffer s;
        data.write(&s);

		FastPathUpdatePDU hdr(FASTPATH_UPDATETYPE_BITMAP, 0, s.length());
		hdr.prepend(&s);

        _fastPathSender->sendFastPath(0, &s);
    } else {
        // slow path case
        BitmapUpdateDataPDU data;
        data.numberRectangles = bitmapDatas.size();
        data.rectangles = bitmapDatas;

        Buffer s;
        data.write(&s);
        sendDataPDU(UPDATETYPE_BITMAP, &s);
    }
}
