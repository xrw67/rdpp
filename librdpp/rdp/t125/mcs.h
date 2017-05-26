/*
 * Implement Multi-Channel Service
 *
 * Each channel have a particular role.
 * The main channel is the graphical channel.
 * It exist channel for file system order, audio channel, clipboard etc...
 */
#ifndef _RDP_T125_MCS_H_
#define _RDP_T125_MCS_H_

#include <core/config.h>
#include <core/layer.h>
#include <rdp/t125/gcc.h>
#include <vector>
#include <map>

namespace rdpp {

    class X224Layer;
    class ServerSecLayer;
    class ClientSettings;
    class ServerSettings;
    class MCSProxySender;

    /// @summary: Message type
    enum Message
    {
        MCS_TYPE_CONNECT_INITIAL = 0x65,
        MCS_TYPE_CONNECT_RESPONSE = 0x66,
    };

    /// @summary: Domain MCS PDU header
    enum DomainMCSPDU
    {
        ERECT_DOMAIN_REQUEST = 1,
        DISCONNECT_PROVIDER_ULTIMATUM = 8,
        ATTACH_USER_REQUEST = 10,
        ATTACH_USER_CONFIRM = 11,
        CHANNEL_JOIN_REQUEST = 14,
        CHANNEL_JOIN_CONFIRM = 15,
        SEND_DATA_REQUEST = 25,
        SEND_DATA_INDICATION = 26,
    };

    /// @summary: Channel id of main channels use in RDP
    enum Channel
    {
        MCS_GLOBAL_CHANNEL = 1003,
        MCS_USERCHANNEL_BASE = 1001,
    };

    /// @summary: Multiple Channel Service layer
    /// the main layer of RDP protocol
    /// is why he can do everything and more!
    class MCSLayer : public Layer
    {
    public:
        struct VirtualChannelLayer {
            string channelDef;
            Layer *layer;
        };

        /// @param presentation: {Layer} presentation layer
        /// @param virtualChannels : {Array(Layer]} list additional channels like rdpsnd...[tuple(mcs.ChannelDef, layer)]
        /// @param receiveOpcode : {integer} opcode check when receive data
        /// @param sendOpcode : {integer} opcode use when send data
        MCSLayer(Layer *presentation, uint8_t receiveOpcode, uint8_t sendOpcode);
        
        /// @summary: Send disconnect provider ultimatum
        virtual void close();

        /// @summary: All channels are connected to MCS layer
        /// Send connect to upper channel
        /// And prepare MCS layer to receive data
        void allChannelConnected();

        /// @summary: Specific send function for channelId
        void send(uint16_t channelId, Buffer *data);

        /// @summary: Main receive method
        void recvData(Buffer *data);

        /// @summary: Write a special domain parameter structure
        /// use in connection sequence
        /// @param maxChannels: {integer} number of MCS channel use
        /// @param maxUsers : {integer} number of MCS user used(1)
        /// @param maxTokens : {integer} unknown
        /// @param maxPduSize : {integer} unknown
        /// @return: {Tuple(type)} domain parameter structure
        void writeDomainParams(Buffer *s, uint32_t maxChannels, uint32_t maxUsers,
                               uint32_t maxTokens, uint32_t maxPduSize);

        /// @summary: Write MCS PDU header
        /// @param mcsPdu: {integer} PDU code
        /// @param options : {integer} option contains in header
        /// @return: {integer}
        void writeMCSPDUHeader(Buffer *s, uint8_t mcsPdu, uint32_t options = 0);

        /// @summary: Read mcsPdu header and return options parameter
        /// @param opcode: {integer} opcode
        /// @param mcsPdu : {integer} mcsPdu will be checked
        /// @return: {boolean} true if opcode is correct
        bool readMCSPDUHeader(Buffer *s, uint32_t opcode, uint32_t mcsPdu);

        /// @summary: Read domain parameters structure
        /// @param s: {Buffer}
        /// @return: {Tuple} (max_channels, max_users, max_tokens, max_pdu_size)
        bool readDomainParams(Buffer *s, uint32_t &maxChannels, uint32_t &maxUsers,
                              uint32_t &maxTokens, uint32_t &maxPduSize);

        /// @return: {integer} mcs user id
        /// @see: mcs.IGCCConfig
        uint16_t getUserId() { return _userId; }

        /// @return: {gcc.Settings} mcs layer gcc client settings
        /// @see: mcs.IGCCConfig
        ClientSettings &getGCCClientSettings() { return _clientSettings; }

        /// @return: {gcc.Settings} mcs layer gcc server settings
        /// @see: mcs.IGCCConfig
        ServerSettings &getGCCServerSettings() { return _serverSettings; }

    protected:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(MCSLayer);

        X224Layer *transport();

        typedef std::map<uint32_t, shared_ptr<MCSProxySender>> ChannelMap;
        ChannelMap _channels;

        ClientSettings _clientSettings;
        ServerSettings _serverSettings;

        uint8_t _sendOpcode;
        uint8_t _receiveOpcode;
        uint16_t _userId;

        std::vector<Layer *> _virtualChannels;

	private:
		virtual void send(Buffer *s) {}
    };

    /// @summary: Client automata of multiple channel service layer
    class ClientMCSLayer : public MCSLayer
    {
    public:
        /// @param presentation : {Layer} presentation layer
        /// @param virtualChannels : {Array(Layer)} list additional channels like rdpsnd...[tuple(mcs.ChannelDef, layer)]
        ClientMCSLayer(Layer *presentation);
        
        /// @summary: Connect message in client automata case
        /// Send ConnectInitial
        /// Wait ConnectResponse
        void connect();

        /// @summary: Send sendChannelJoinRequest message on next disconnect channel
        /// Send channel request or connect upper layer if all channels are connected
        /// Wait channel confirm
        void connectNextChannel();

        /// @summary: Receive MCS connect response from server
        /// Send Erect domain Request
        /// Send Attach User Request
        /// Wait Attach User Confirm
        void recvConnectResponse(Buffer *data);

        /// @summary: Receive an attach user confirm
        /// Send Connect Channel
        void recvAttachUserConfirm(Buffer *data);

        /// @summary: Receive a channel join confirm from server
        /// client automata function
        void recvChannelJoinConfirm(Buffer *data);

        /// @summary: Send connect initial packet
        /// client automata function
        void sendConnectInitial();

        /// @summary: Send a formated erect domain request for RDP connection
        void sendErectDomainRequest();

        /// @summary: Send a formated attach user request for RDP connection
        void sendAttachUserRequest();

        /// @summary: Send a formated Channel join request from client to server
        /// client automata function
        /// @param channelId: {integer} id of channel requested
        void sendChannelJoinRequest(uint16_t channelId);

    private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(ClientMCSLayer);

        bool _isGlobalChannelRequested;
        bool _isUserChannelRequested;
        uint32_t _nbChannelRequested;
    };

    /// @summary: Server automata of multiple channel service layer
    class ServerMCSLayer : public MCSLayer
    {
    public:
        /// @param presentation : {Layer} presentation layer
        /// @param virtualChannels : {List(Layer)} list additional channels like rdpsnd...[tuple(mcs.ChannelDef, layer)]
        ServerMCSLayer(Layer *presentation);

        /// @summary: Connect message for server automata
        /// Wait Connect Initial
        void connect();

        /// @summary: Receive MCS connect initial from client
        /// Send Connect Response
        /// Wait Erect Domain Request
        /// @param data: {Buffer}
        void recvConnectInitial(Buffer *data);

        /// @summary: Receive erect domain request
        /// Wait Attach User Request
        /// @param data: {Buffer}
        void recvErectDomainRequest(Buffer *data);

        /// @summary: Receive Attach user request
        /// Send Attach User Confirm
        /// Wait Channel Join Request
        /// @param data: {Buffer}
        void recvAttachUserRequest(Buffer *data);

        /// @summary: Receive for each client channel a request
        /// Send Channel Join Confirm or Connect upper layer when all channel are joined
        /// @param data: {Buffer}
        void recvChannelJoinRequest(Buffer *data);

        /// @summary: Send connect response
        void sendConnectResponse();

        /// @summary: Send attach user confirm
        void sendAttachUserConfirm();

        /// @summary: Send a confirm channel(or not) to client
        /// @param channelId: {integer} id of channel
        /// @param confirm : {boolean} connection state
        void sendChannelJoinConfirm(uint32_t channelId, bool confirm);
        
    private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(ServerMCSLayer);

        ServerSecLayer *presentation();

        uint32_t _nbChannelConfirmed;
    };

    /// @summary: Proxy use to set as transport layer for upper channel
    /// use to abstract channel id for presentation layer
    class MCSProxySender : public Layer
    {
    public:
        /// @param presentation: {Layer} presentation layer
        /// @param mcs : {MCSLayer} MCS layer use as proxy
        /// @param channelId : {integer} channel id for presentation layer
        MCSProxySender(Layer *presentation, MCSLayer *mcs, uint16_t channelId)
            : Layer(presentation), _mcs(mcs), _channelId(channelId)
        {}

		void recv(Buffer *data)
		{
			_presentation->recv(data);
		}

        /// @summary: A send proxy function, use channel id and specific
        /// send function of MCS layer
        /// @param data: {type.Type | Tuple}
        void send(Buffer *data)
        {
            _mcs->send(_channelId, data);
        }

        ///  @summary: Close wrapped layer
        void close()
        {
            _mcs->close();
        }

        /// @return: {integer} mcs user id
        /// @see: mcs.IGCCConfig
        uint16_t getUserId()
        {
            return _mcs->getUserId();
        }

        /// @return: {integer} return channel id of proxy
        /// @see: mcs.IGCCConfig
        uint16_t getChannelId()
        {
            return _channelId;
        }

        /// @return: {gcc.Settings} mcs layer gcc client settings
        /// @see: mcs.IGCCConfig
        ClientSettings &getGCCClientSettings()
        {
            return _mcs->getGCCClientSettings();
        }

        /// @return: {gcc.Settings} mcs layer gcc server settings
        /// @see: mcs.IGCCConfig
        ServerSettings &getGCCServerSettings()
        {
            return _mcs->getGCCServerSettings();
        }

    private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(MCSProxySender);

        MCSLayer *_mcs;
        uint16_t _channelId;
    };

} // namespace rdpp

#endif // _RDP_T125_MCS_H_
