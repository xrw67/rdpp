#include <rdp/t125/mcs.h>
#include <rdp/x224.h>
#include <rdp/sec.h>
#include <core/per.h>
#include <core/ber.h>
#include <core/crypto.h>
#include <core/log.h>

#define TAG "MCS"

using namespace rdpp;

MCSLayer::MCSLayer(Layer *presentation, uint8_t receiveOpcode, uint8_t sendOpcode)
    : Layer(presentation)
    , _sendOpcode(sendOpcode) // send opcode
    , _receiveOpcode(receiveOpcode) // receive opcode
    , _userId(1 + MCS_USERCHANNEL_BASE) // default user Id
{
    // list of channel use in this layer and connection state
    _channels[MCS_GLOBAL_CHANNEL] = rdpp::make_shared<MCSProxySender>(presentation, this, MCS_GLOBAL_CHANNEL);
}

void MCSLayer::close()
{
    Buffer s;

    writeMCSPDUHeader(&s, DISCONNECT_PROVIDER_ULTIMATUM, 1);
    PER::writeEnumerates(&s, 0x80);
    s.append(6, '\x00');
    _transport->send(&s);
    
    _transport->close();
}

void MCSLayer::allChannelConnected()
{
	RDPP_LOG(TAG, TRACE) << "MCSLayer::allChannelConnected";

    // connection is done
    setNextState(rdpp::bind(&MCSLayer::recvData, this, _1));
    // try connection on all requested channel
    ChannelMap::iterator it;
    for (it = _channels.begin(); it != _channels.end(); ++it) {
        shared_ptr<MCSProxySender> sender(it->second);
        sender->connect();
    }
}

void MCSLayer::send(uint16_t channelId, Buffer *data)
{
    Buffer s;

    writeMCSPDUHeader(&s, _sendOpcode);
    PER::writeInteger16(&s, _userId, MCS_USERCHANNEL_BASE);
    PER::writeInteger16(&s, channelId);
    s.appendUInt8(0x70);
    PER::writeLength(&s, data->length());
    s.append(data);
    _transport->send(&s);
}

void MCSLayer::recvData(Buffer *data)
{
    uint16_t channelId;
    uint16_t integer16;
    uint8_t enumerated;
    uint8_t opcode = data->readUInt8();

    if (readMCSPDUHeader(data, opcode, DISCONNECT_PROVIDER_ULTIMATUM)) {
        RDPP_LOG(TAG, INFO) << "MCS DISCONNECT_PROVIDER_ULTIMATUM";
        _transport->close();
        return;
    }
    // client case
    else if (!readMCSPDUHeader(data, opcode, _receiveOpcode)) {
        RDPP_LOG(TAG, ERROR) << "Invalid expected MCS opcode receive data";
        _transport->close();
        return;
    }

    // server user id
    PER::readInteger16(data, integer16, MCS_USERCHANNEL_BASE);
    PER::readInteger16(data, channelId);
    PER::readEnumerates(data, enumerated);
    PER::readLength(data, integer16);

    // channel id doesn't match a requested layer
    if (_channels.end() == _channels.find(channelId)) {
        RDPP_LOG(TAG, ERROR) << "receive data for an unconnected layer, channel id=" << channelId;
        return;
    }
    
    _channels[channelId]->recv(data);
}

void MCSLayer::writeDomainParams(Buffer *s, uint32_t maxChannels, uint32_t maxUsers,
                                 uint32_t maxTokens, uint32_t maxPduSize)
{
    Buffer domainParam;
    BER::writeInteger(&domainParam, maxChannels);
    BER::writeInteger(&domainParam, maxUsers);
    BER::writeInteger(&domainParam, maxTokens);
    BER::writeInteger(&domainParam, 1);
    BER::writeInteger(&domainParam, 0);
    BER::writeInteger(&domainParam, 1);
    BER::writeInteger(&domainParam, maxPduSize);
    BER::writeInteger(&domainParam, 2);

    BER::writeUniversalTag(s, BER::BER_TAG_SEQUENCE, true);
    BER::writeLength(s, domainParam.length());
    s->append(domainParam);
}

void MCSLayer::writeMCSPDUHeader(Buffer *s, uint8_t mcsPdu, uint32_t options)
{
    s->appendUInt8((mcsPdu << 2) | options);
}

bool MCSLayer::readMCSPDUHeader(Buffer *s, uint32_t opcode, uint32_t mcsPdu)
{
    return (opcode >> 2) == mcsPdu;
}

bool MCSLayer::readDomainParams(Buffer *s, uint32_t &maxChannels, uint32_t &maxUsers,
                                uint32_t &maxTokens, uint32_t &maxPduSize)
{
    int length;
    uint32_t value;

    if (!BER::readUniversalTag(s, BER::BER_TAG_SEQUENCE, true)) {
        RDPP_LOG(TAG, ERROR) << "bad BER tags";
        return false;
    }
    if (!BER::readLength(s, length))
		return false;
    if (!BER::readInteger(s, maxChannels))
		return false;
    if (!BER::readInteger(s, maxUsers))
		return false;
    if (!BER::readInteger(s, maxTokens))
		return false;
    if (!BER::readInteger(s, value))
		return false;
    if (!BER::readInteger(s, value))
		return false;
    if (!BER::readInteger(s, value))
		return false;
    if (!BER::readInteger(s, maxPduSize))
		return false;
    if (!BER::readInteger(s, value))
		return false;
    return true;
}

X224Layer *MCSLayer::transport() 
{
    return dynamic_cast<X224Layer *>(_transport);
}

//
// ClientMCSLayer
//

ClientMCSLayer::ClientMCSLayer(Layer *presentation)
    : MCSLayer(presentation, SEND_DATA_INDICATION, SEND_DATA_REQUEST)
    , _isGlobalChannelRequested(false) // // use to know state of static channel
    , _isUserChannelRequested(false)
    , _nbChannelRequested(0) // nb channel requested
{
}

void ClientMCSLayer::connect()
{
	RDPP_LOG(TAG, TRACE) << "ClientMCSLayer::connect()";

    _clientSettings.core.serverSelectedProtocol = transport()->selectedProtocol();

    // ask for virtual channel
    //for (size_t i = 0; i < _virtualChannels.size(); ++i) {
    //    shared_ptr<ChannelDef> def(new ChannelDef);
    //    strncpy(def->name, _virtualChannels[i].channelDef.c_str(), 7);
    //    _clientSettings->network->channelDefArray.push_back(def);
    //}

    // send connect initial
    sendConnectInitial();
    // next wait response
    setNextState(rdpp::bind(&ClientMCSLayer::recvConnectResponse, this, _1));
}

void ClientMCSLayer::connectNextChannel()
{
	RDPP_LOG(TAG, TRACE) << "ClientMCSLayer::connectNextChannel()";

    setNextState(rdpp::bind(&ClientMCSLayer::recvChannelJoinConfirm, this, _1));
    // global channel
    if (!_isGlobalChannelRequested) {
        sendChannelJoinRequest(MCS_GLOBAL_CHANNEL);
        _isGlobalChannelRequested = true;
        return;
    }

    // user channel
    if (!_isUserChannelRequested) {
        sendChannelJoinRequest(_userId);
        _isUserChannelRequested = true;
        return;
    }

    // static virtual channel
    if (_nbChannelRequested < _serverSettings.network.channelCount) {
        uint16_t channelId = _serverSettings.network.channelIdArray[_nbChannelRequested];
        _nbChannelRequested += 1;
        sendChannelJoinRequest(channelId);
        return;
    }

    allChannelConnected();
}

void ClientMCSLayer::recvConnectResponse(Buffer *data)
{
	RDPP_LOG(TAG, TRACE) << "ClientMCSLayer::recvConnectResponse(" << data->length() << " Bytes)";

    int length;
    uint8_t enumerated;
    uint32_t value;

    if (!BER::readApplicationTag(data, MCS_TYPE_CONNECT_RESPONSE, length))
		return;
    if (!BER::readEnumerated(data, enumerated))
		return;
    if (!BER::readInteger(data, value))
		return;

    uint32_t maxChannels, maxUsers, maxTokens, maxPduSize;
    if (!readDomainParams(data, maxChannels, maxUsers, maxTokens, maxPduSize))
		return;

    if (!BER::readUniversalTag(data, BER::BER_TAG_OCTET_STRING, false)) {
        RDPP_LOG(TAG, ERROR) << "invalid expected BER tag";
        return;
    }

    if (!BER::readLength(data, length)) // gccRequestLength
		return;
    if (length != data->length()) {
        RDPP_LOG(TAG, ERROR) << "bad size of GCC request";
        return;
    }
    _serverSettings.readConferenceCreateResponse(data);

    // send domain request
    sendErectDomainRequest();
    // send attach user request
    sendAttachUserRequest();
    // now wait user confirm from server
    setNextState(rdpp::bind(&ClientMCSLayer::recvAttachUserConfirm, this, _1));
}

void ClientMCSLayer::recvAttachUserConfirm(Buffer *data)
{
	RDPP_LOG(TAG, TRACE) << "ClientMCSLayer::recvAttachUserConfirm(" << data->length() << " Bytes)";

    uint8_t opcode = data->readUInt8();

    if (!readMCSPDUHeader(data, opcode, ATTACH_USER_CONFIRM)) {
        RDPP_LOG(TAG, ERROR) << "Invalid MCS PDU : ATTACH_USER_CONFIRM expected";
        return;
    }

    uint8_t enumerated;
    PER::readEnumerates(data, enumerated);
    if (enumerated != 0) {
        RDPP_LOG(TAG, ERROR) << "Server reject user";
        return;
    }
    PER::readInteger16(data, _userId, MCS_USERCHANNEL_BASE);
    connectNextChannel();
}

void ClientMCSLayer::recvChannelJoinConfirm(Buffer *data)
{
	RDPP_LOG(TAG, TRACE) << "ClientMCSLayer::recvChannelJoinConfirm(" << data->length() << " Bytes)";

    uint8_t opcode = data->readUInt8();

    if (!readMCSPDUHeader(data, opcode, CHANNEL_JOIN_CONFIRM)) {
        RDPP_LOG(TAG, ERROR) << "Invalid MCS PDU : CHANNEL_JOIN_CONFIRM expected";
        return;
    }

    uint8_t confirm;
    PER::readEnumerates(data, confirm);

    uint16_t userId;
    PER::readInteger16(data, userId, MCS_USERCHANNEL_BASE);
    if (_userId != userId) {
        RDPP_LOG(TAG, ERROR) << "Invalid MCS User Id";
        return;
    }

    uint16_t channelId;
    PER::readInteger16(data, channelId);
    // must confirm global channel and user channel
    if ((confirm != 0) && (channelId == MCS_GLOBAL_CHANNEL || channelId == _userId)) {
        RDPP_LOG(TAG, ERROR) << "Server must confirm static channel";
        return;
    }

    //if (confirm == 0) {
    //    ServerNetworkData &serverNet = _serverSettings.network;
    //    for (size_t i = 0; i < serverNet.channelIdArray.size(); ++i) {
    //        if (channelId == serverNet.channelIdArray[i])
    //             _channels[channelId] = _virtualChannels[i].layer;
    //    }
    //}
    
    connectNextChannel();
}

void ClientMCSLayer::sendConnectInitial()
{
    Buffer ccReqStream;
    _clientSettings.writeConferenceCreateRequest(&ccReqStream);

    Buffer tmp;
    BER::writeOctetString(&tmp, "\x01", 1);
    BER::writeOctetString(&tmp, "\x01", 1);
    BER::writeBoolean(&tmp, true);
    writeDomainParams(&tmp, 34, 2, 0, 0xffff);
    writeDomainParams(&tmp, 1, 1, 1, 0x420);
    writeDomainParams(&tmp, 0xffff, 0xfc17, 0xffff, 0xffff);
	BER::writeOctetString(&tmp, ccReqStream.c_str(), ccReqStream.length());

    Buffer s;
    BER::writeApplicationTag(&s, MCS_TYPE_CONNECT_INITIAL, tmp.length());
    s.append(tmp);
	RDPP_LOG(TAG, TRACE) << "ClientMCSLayer::sendConnectInitial, " << s.length() << " Bytes";
    _transport->send(&s);
}

void ClientMCSLayer::sendErectDomainRequest()
{
    Buffer s;
    writeMCSPDUHeader(&s, ERECT_DOMAIN_REQUEST);
    PER::writeInteger(&s, 0);
    PER::writeInteger(&s, 0);
	RDPP_LOG(TAG, TRACE) << "ClientMCSLayer::sendErectDomainRequest, " << s.length() << " Bytes";
    _transport->send(&s);
}

void ClientMCSLayer::sendAttachUserRequest()
{
    Buffer s;
    writeMCSPDUHeader(&s, ATTACH_USER_REQUEST);
	RDPP_LOG(TAG, TRACE) << "ClientMCSLayer::sendAttachUserRequest, " << s.length() << " Bytes";
    _transport->send(&s);
}

void ClientMCSLayer::sendChannelJoinRequest(uint16_t channelId)
{
    Buffer s;
    writeMCSPDUHeader(&s, CHANNEL_JOIN_REQUEST);
    PER::writeInteger16(&s, _userId, MCS_USERCHANNEL_BASE);
    PER::writeInteger16(&s, channelId);
	RDPP_LOG(TAG, TRACE) << "ClientMCSLayer::sendChannelJoinRequest, " << s.length() << " Bytes";
    _transport->send(&s);
}

//
// ServerMCSLayer
//

ServerMCSLayer::ServerMCSLayer(Layer *presentation)
    : MCSLayer(presentation, SEND_DATA_REQUEST, SEND_DATA_INDICATION)
    , _nbChannelConfirmed(0) // nb channel requested
{
}

void ServerMCSLayer::connect()
{
	RDPP_LOG(TAG, TRACE) << "ServerMCSLayer::connect()";

    // basic rdp security layer
    if (transport()->selectedProtocol() == 0) {
        _serverSettings.security.encryptionMethod = ENCRYPTION_METHOD_128BIT;
        _serverSettings.security.encryptionLevel = ENCRYPTION_LEVEL_HIGH;
		_serverSettings.security.serverRandomLen = 32;
        Rsa::random(_serverSettings.security.serverRandom, 32);
		presentation()->getCertificate(_serverSettings.security.serverCertificate);
		_serverSettings.security.serverCertLen = _serverSettings.security.serverCertificate.size();
    }

    _serverSettings.core.clientRequestedProtocol = transport()->requestedProtocol();
    setNextState(rdpp::bind(&ServerMCSLayer::recvConnectInitial, this, _1));
}

void ServerMCSLayer::recvConnectInitial(Buffer *data)
{
	RDPP_LOG(TAG, TRACE) << "ServerMCSLayer::recvConnectInitial(" << data->length() << " Bytes)";

    int length;
    string value;
    bool bValue;

    if (!BER::readApplicationTag(data, MCS_TYPE_CONNECT_INITIAL, length))
		return;
	if (!BER::readOctetString(data, value))
		return;
    if (!BER::readOctetString(data, value))
		return;
    if (!BER::readBoolean(data, bValue)) {
        RDPP_LOG(TAG, ERROR) << "invalid expected BER boolean tag";
        return;
    }

    uint32_t maxChannels, maxUsers, maxTokens, maxPduSize;
    if (!readDomainParams(data, maxChannels, maxUsers, maxTokens, maxPduSize))
		return;
    if (!readDomainParams(data, maxChannels, maxUsers, maxTokens, maxPduSize))
		return;
    if (!readDomainParams(data, maxChannels, maxUsers, maxTokens, maxPduSize))
		return;

    if (!BER::readOctetString(data, value))
		return;

	Buffer s;
	s.append(value);
    _clientSettings.readConferenceCreateRequest(&s);

	_serverSettings.network.channelCount = _clientSettings.network.channelDefArray.size();
    for (size_t i = 0; i < _clientSettings.network.channelDefArray.size(); ++i) {
        _serverSettings.network.channelIdArray.push_back(i + 1 + MCS_GLOBAL_CHANNEL);

        // if channel can be handle by serve add it
        //const string channelDef(_clientSettings->network.channelDefArray[i]->name);
        //for (size_t j = 0; j < _virtualChannels.size(); ++j) {
        //    if (channelDef == _virtualChannels[i].channelDef)
        //        _channels[i + MCS_GLOBAL_CHANNEL] = _virtualChannels[i].layer;
        //}
    }

    sendConnectResponse();
    setNextState(rdpp::bind(&ServerMCSLayer::recvErectDomainRequest, this, _1));
}

void ServerMCSLayer::recvErectDomainRequest(Buffer *data)
{
	RDPP_LOG(TAG, TRACE) << "ServerMCSLayer::recvErectDomainRequest(" << data->length() << " Bytes)";

    uint8_t opcode = data->readUInt8();
    if (!readMCSPDUHeader(data, opcode, ERECT_DOMAIN_REQUEST)) {
        RDPP_LOG(TAG, ERROR) << "Invalid MCS PDU : ERECT_DOMAIN_REQUEST expected";
        return;
    }

    uint32_t integer32;
    if (!PER::readInteger(data, integer32))
		return;
    if (!PER::readInteger(data, integer32))
		return;

    setNextState(rdpp::bind(&ServerMCSLayer::recvAttachUserRequest, this, _1));
}

void ServerMCSLayer::recvAttachUserRequest(Buffer *data)
{
	RDPP_LOG(TAG, TRACE) << "ServerMCSLayer::recvAttachUserRequest(" << data->length() << " Bytes)";

    uint8_t opcode = data->readUInt8();
    if (!readMCSPDUHeader(data, opcode, ATTACH_USER_REQUEST)) {
        RDPP_LOG(TAG, ERROR) << "Invalid MCS PDU : ATTACH_USER_REQUEST expected";
        return;
    }
    sendAttachUserConfirm();
    setNextState(rdpp::bind(&ServerMCSLayer::recvChannelJoinRequest, this, _1));
}

void ServerMCSLayer::recvChannelJoinRequest(Buffer *data)
{
    uint8_t opcode = data->readUInt8();
    if (!readMCSPDUHeader(data, opcode, CHANNEL_JOIN_REQUEST)) {
        RDPP_LOG(TAG, ERROR) << "Invalid MCS PDU : CHANNEL_JOIN_REQUEST expected";
        return;
    }

    uint16_t userId = 0;
    PER::readInteger16(data, userId, MCS_USERCHANNEL_BASE);
    if (userId != _userId) {
        RDPP_LOG(TAG, ERROR) << "Invalid MCS User Id";
        return;
    }

    uint16_t channelId;
    PER::readInteger16(data, channelId);
	
	RDPP_LOG(TAG, TRACE) << "ServerMCSLayer::recvChannelJoinRequest(userId=" << _userId << ", channelId=" << channelId << ")";

    // actually algo support virtual channel but RDPY have no virtual channel
    bool confirm;
    if (_channels.end() != _channels.find(channelId) || channelId == _userId)
        confirm = 0;
    else
        confirm = 1;
    sendChannelJoinConfirm(channelId, confirm);
    _nbChannelConfirmed += 1;
    if (_nbChannelConfirmed == _serverSettings.network.channelCount + 2)
        allChannelConnected();
}

void ServerMCSLayer::sendConnectResponse()
{
    Buffer ccReq;
    _serverSettings.writeConferenceCreateResponse(&ccReq);

    Buffer tmp;
    BER::writeEnumerated(&tmp, 0); // result = 0;
    BER::writeInteger(&tmp, 0); // connect id
    writeDomainParams(&tmp, 22, 3, 0, 0xfff8);
	BER::writeOctetString(&tmp, ccReq.c_str(), ccReq.length());

    Buffer s;
    BER::writeApplicationTag(&s, MCS_TYPE_CONNECT_RESPONSE, tmp.length());
    s.append(tmp);

	RDPP_LOG(TAG, TRACE) << "sendConnectResponse";
    _transport->send(&s);
}

void ServerMCSLayer::sendAttachUserConfirm()
{
    Buffer s;
    writeMCSPDUHeader(&s, ATTACH_USER_CONFIRM, 2);
    PER::writeEnumerates(&s, 0);
    PER::writeInteger16(&s, _userId, MCS_USERCHANNEL_BASE);

	RDPP_LOG(TAG, TRACE) << "sendAttachUserConfirm(userId= " << _userId << ")";
    _transport->send(&s);
}

void ServerMCSLayer::sendChannelJoinConfirm(uint32_t channelId, bool confirm)
{
    Buffer s;
    writeMCSPDUHeader(&s, CHANNEL_JOIN_CONFIRM, 2);
    PER::writeEnumerates(&s, confirm);
    PER::writeInteger16(&s, _userId, MCS_USERCHANNEL_BASE);
    PER::writeInteger16(&s, channelId);
    PER::writeInteger16(&s, channelId);

	RDPP_LOG(TAG, TRACE) << "sendChannelJoinConfirm(userid="<< _userId << ", channelId:" << channelId << ", confirm=" << confirm << ")";
    _transport->send(&s);
}

ServerSecLayer *ServerMCSLayer::presentation()
{
    return dynamic_cast<ServerSecLayer *>(_presentation);
}
