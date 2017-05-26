/**
 * Transport packet layer implementation
 * Use to build correct size packet and handle slow path and fast path mode
 */
#ifndef _RDPP_RDP_TPKT_H_
#define _RDPP_RDP_TPKT_H_

#include <core/config.h>
#include <core/layer.h>

namespace rdpp {

    /// @see: http://msdn.microsoft.com/en-us/library/cc240621.aspx
    /// @see: http://msdn.microsoft.com/en-us/library/cc240589.aspx
    enum FastPathAction {
        FASTPATH_ACTION_FASTPATH = 0x0,
        FASTPATH_ACTION_X224 = 0x3,
    };

    /// @see: http://msdn.microsoft.com/en-us/library/cc240621.aspx
    enum SecFlags {
        // hihi 'secure' checksum but private key is public !!!
        FASTPATH_OUTPUT_SECURE_CHECKSUM = 0x1,
        FASTPATH_OUTPUT_ENCRYPTED = 0x2,
    };

    /// @summary:  TPKT layer in RDP protocol stack
    ///             represent the Raw Layer in stack (first layer)
    ///             This layer only handle size of packet and determine if is a fast path packet
    class TPKTLayer : public Layer, public FastPathLayer
    {
    public:
	    TPKTLayer(Layer *presentation, FastPathLayer *fastPathListener,
                  RdpTransport *rdpTransport);

	    /// @summary: Call  return transport layer
	    virtual void connect();

		virtual void close();

        /// @summary: main event of received data
        void dataReceived(Buffer *data);

	    /// @summary: Send encompassed data
	    virtual void send(Buffer *data);

        /// @param fastPathS: {Type | Tuple} type transform to stream and send as fastpath
	    virtual void sendFastPath(uint16_t secFlag, Buffer *data);

    private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(TPKTLayer);

		virtual void recvFastPath(uint16_t secFlag, Buffer *data) {}

        /// @summary:  Set next automata callback,
        ///             But this callback will be only called when
        ///             data have expectedLen
        /// @param expectedLen: in bytes length use to call next state
        /// @param callback : callback call when expected length bytes is received
        void expect(size_t expectedLen, const Layer::OnRecvCallback &callback);
    
        /// @summary: Read header of TPKT packet
        void readHeader(Buffer *data);

        /// @summary: Header may be on 4 bytes
        void readExtendedHeader(Buffer *data);

        /// @summary: Fast path header may be on 1 byte more
        void readExtendedFastPathHeader(Buffer *data);

        /// @summary: Fast path data
        void readFastPath(Buffer *data);

        /// @summary: Read classic TPKT packet, last state in tpkt automata
        void readData(Buffer *data);

	private:
        // len of next packet pass to next state function
        size_t _expectedLen;

        RdpTransport *_rdpTransport;

	    uint8_t _lastShortLength;
	    uint8_t _secFlag;
    };

} // namespace rdpp

#endif // _RDPP_RDP_TPKT_H_
