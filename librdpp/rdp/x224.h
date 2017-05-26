/**
 * Implement transport PDU layer
 *
 * This layer have main goal to negociate SSL transport
 * RDP basic security is supported only on client side
 */

#ifndef _RDPP_RDP_X224_H_
#define _RDPP_RDP_X224_H_

#include <core/config.h>
#include <core/layer.h>

namespace rdpp {

    /// @summary: Message type
    enum X224MessageType
    {
        X224_TPDU_CONNECTION_REQUEST = 0xE0,
        X224_TPDU_CONNECTION_CONFIRM = 0xD0,
        X224_TPDU_DISCONNECT_REQUEST = 0x80,
        X224_TPDU_DATA = 0xF0,
        X224_TPDU_ERROR = 0x70,
    };

    /// @summary: Negotiation header
    enum NegociationType
    {
        TYPE_RDP_NEG_REQ = 0x01,
        TYPE_RDP_NEG_RSP = 0x02,
        TYPE_RDP_NEG_FAILURE = 0x03,
    };

    /// @summary: Protocols available for x224 layer
    /// @see: https://msdn.microsoft.com/en-us/library/cc240500.aspx
    enum Protocols
    {
        PROTOCOL_RDP = 0x00000000,
        PROTOCOL_SSL = 0x00000001,
        PROTOCOL_HYBRID = 0x00000002,
		PROTOCOL_RDSTLS = 0x00000004,
        PROTOCOL_HYBRID_EX = 0x00000008,
    };

    /// @summary: Protocol negotiation failure code
    enum NegotiationFailureCode
    {
        SSL_REQUIRED_BY_SERVER = 0x00000001,
        SSL_NOT_ALLOWED_BY_SERVER = 0x00000002,
        SSL_CERT_NOT_ON_SERVER = 0x00000003,
        INCONSISTENT_FLAGS = 0x00000004,
        HYBRID_REQUIRED_BY_SERVER = 0x00000005,
        SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 0x00000006,
    };

    /// @summary:  x224 layer management
    class X224Layer : public Layer
    {
    public:
        X224Layer(Layer *presentation, RdpTransport *rdpTransport);

        /// @summary: Read data header from packet
        ///            And pass to presentation layer
        void recvData(Buffer *s);

        /// @summary: Write message packet for TPDU layer
        ///            Add TPDU header
        virtual void send(Buffer *s);

        uint32_t requestedProtocol() const { return _requestedProtocol; }
        uint32_t selectedProtocol() const { return _selectedProtocol; }
        void setRequestedPtotocol(uint32_t proto) { _requestedProtocol = proto; }

    protected:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(X224Layer);

		RdpTransport *_rdpTransport;
        uint32_t _requestedProtocol;
        uint32_t _selectedProtocol;
    };

    class ClientX224Layer : public X224Layer
    {
    public:
        ClientX224Layer(Layer *presentation, RdpTransport *rdpTransport, NlaConnector *nlaConnector);

        /// @summary: Connection request for client send a connection request packet
        virtual void connect();

    private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(ClientX224Layer);

        /// @summary:  Write connection request message
        ///             Next state is recvConnectionConfirm
        /// @see: http://msdn.microsoft.com/en-us/library/cc240500.aspx
        void sendConnectionRequest();

        /// @summary:  Receive connection confirm message
        ///             Next state is recvData 
        ///             Call connect on presentation layer if all is good
        /// @param data: Buffer that contain connection confirm
        /// @see: response -> http://msdn.microsoft.com/en-us/library/cc240506.aspx
        /// @see: failure ->http://msdn.microsoft.com/en-us/library/cc240507.aspx
        void recvConnectionConfirm(Buffer *s);

	private:
        NlaConnector *_nlaConnector;
    };

    /// @summary: Server automata of X224 layer
    class ServerX224Layer : public X224Layer
    {
    public:
        /// @param presentation: {layer} upper layer, MCS layer in RDP case
        ServerX224Layer(Layer *presentation, RdpTransport *rdpTransport);

        // @summary: Connection request for server wait connection request packet from client
        void connect();

    private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(ServerX224Layer);

        /// @summary:  Read connection confirm packet
        ///             Next state is send connection confirm
        /// @see : http ://msdn.microsoft.com/en-us/library/cc240470.aspx
        void recvConnectionRequest(Buffer *s);

        /// @summary:  Write connection confirm message
        ///             Start TLS connection
        ///             Next state is recvData
        /// @see : http://msdn.microsoft.com/en-us/library/cc240501.aspx
        void sendConnectionConfirm();

	private:
        bool _forceSSL;
    };

} // namespace rdpp

#endif // _RDPP_RDP_X224_H_
