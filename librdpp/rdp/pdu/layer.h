/**
 * Implement the main graphic layer
 *
 * In this layer are managed all mains bitmap update orders end user inputs
 */

#ifndef _RDPP_RDP_PDU_LAYER_H_
#define _RDPP_RDP_PDU_LAYER_H_

#include <vector>
#include <core/config.h>
#include <core/buffer.h>
#include <core/layer.h>
#include <rdp/pdu/caps.h>
#include <rdp/pdu/data.h>

namespace rdpp {

    struct CapabilitySets;
    struct ClientCoreData;

    class SecLayer;
    
	/// @summary: Interface for PDU server automata listener
	class PduClientListener
	{
	public:
		/// @summary: Event call when PDU layer is ready to send events
		virtual void onReady() = 0;

		///  @summary: Event call when Windows session is ready
		virtual void onSessionReady() = 0;

		/// @summary: call when a bitmap data is received from update PDU
		virtual void onUpdate(std::vector<BitmapDataPtr> &rectangles) = 0;

		//TODO virtual recvDstBltOrder(order) = 0;
	};

	class PduServerListener
	{
	public:
		/// @summary: Event call when PDU layer is ready to send 
		virtual void onReady() = 0;

		///  @summary: Event call when slow path input are available
		virtual void onSlowPathInput(uint16_t numEvents, Buffer *slowPathInputEvents) = 0;
	};

    /// @summary: Global channel for MCS that handle session
    /// identification user, licensing management, and capabilities exchange
    class PDULayer : public Layer, public FastPathLayer
    {
    public:
        PDULayer();

        /// @summary: Send a PDU data to transport layer
        /// @param pduMessage: PDU message
        void sendPDU(uint16_t pduType, Buffer *pduMessage);

        /// @summary: Send an PDUData to transport layer
        /// @param pduData: PDU data message
        void sendDataPDU(uint8_t pduType2, Buffer *pduData);

        uint32_t shareId() const { return _shareId; }

		ClientCapabilitySets &clientCapabilitySets() { return _clientCaps; }
		
		ServerCapabilitySets &serverCapabilitySets() { return _serverCaps; }

        SecLayer *transport();

    protected:
        ServerCapabilitySets _serverCaps;
		ClientCapabilitySets _clientCaps;

        uint32_t _shareId;
        bool _clientFastPathSupported;

	private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(PDULayer);

		virtual void send(Buffer *s) {}
		virtual void sendFastPath(uint16_t secFlag, Buffer *data) {}
    };

    /// @summary: Client automata of PDU layer
    class ClientPDULayer : public PDULayer
    {    
    public:
        /// @param listener : PDUClientListener
        ClientPDULayer(PduClientListener *listener);

        /// @summary: Connect message in client automata
        void connect();

        /// @summary: Send PDU close packet and call close method on transport method
        void close();

        /// @summary: Receive demand active PDU which contains
        /// Server capabilities.In this version of RDPY only
        /// Restricted group of capabilities are used.
        /// Send Confirm Active PDU
        /// Send Finalize PDU
        /// Wait Server Synchronize PDU
        /// @param s: Buffer
        void recvDemandActivePDU(Buffer *s);

        /// @summary: Receive from server
        /// Wait Control Cooperate PDU
        /// @param s: Buffer from transport layer
        void recvServerSynchronizePDU(Buffer *s);

        /// @summary: Receive control cooperate PDU from server
        /// Wait Control Granted PDU
        /// @param s: Buffer from transport layer
        void recvServerControlCooperatePDU(Buffer *s);

        /// @summary: Receive last control PDU the granted control PDU
        /// Wait Font map PDU
        /// @param s: Buffer from transport layer
        void recvServerControlGrantedPDU(Buffer *s);

        /// @summary: Last useless connection packet from server to client
        /// Wait any PDU
        /// @param s: Buffer from transport layer
        void recvServerFontMapPDU(Buffer *s);

        /// @summary: Main receive function after connection sequence
        /// @param s: Buffer from transport layer
        void recvPDU(Buffer *s);

        /// @summary: Implement IFastPathListener interface
        /// Fast path is needed by RDP 8.0
        /// @param fastPathS : {Buffer} that contain fast path data
        /// @param secFlag : {SecFlags}
        void recvFastPath(uint16_t secFlag, Buffer *fastPathS);

        /// @summary: read a data PDU object
        /// @param dataPDU: DataPDU object
        void readDataPDU(Buffer *s, uint16_t readLen);

        /// @summary: Read an update data PDU data
        /// dispatch update data
        /// @param: {UpdateDataPDU} object
        void readUpdateDataPDU(Buffer *s, uint16_t readLen);

        /// @summary: Send all client capabilities
        void sendConfirmActivePDU();

        /// @summary: send a synchronize PDU from client to server
        void sendClientFinalizeSynchronizePDU();

        /// @summary: send client input events
        /// @param pointerEvents: list of pointer events
        void sendInputEvents(uint16_t eventType, uint16_t numEvents, Buffer *slowPathInputEvents);

    private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(ClientPDULayer);

		PduClientListener *_listener;
        ClientCoreData *_gccCore;
    };

    /// @summary: Server automata of PDU layer
    class ServerPDULayer : public PDULayer
    {
    public:
        /// @param listener: PDUServerListener
        ServerPDULayer(PduServerListener *listener);

        /// @summary: Connect message for server automata
        void connect();

        /// @summary: Receive confirm active PDU from client
        /// Capabilities exchange
        /// Wait Client Synchronize PDU
        /// @param s: Buffer
        void recvConfirmActivePDU(Buffer *s);

        /// @summary: Receive from client
        /// Wait Control Cooperate PDU
        /// @param s: Buffer from transport layer
        void recvClientSynchronizePDU(Buffer *s);

        /// @summary: Receive control cooperate PDU from client
        /// Wait Control Request PDU
        /// @param s: Buffer from transport layer
        void recvClientControlCooperatePDU(Buffer *s);

        /// @summary: Receive last control PDU the request control PDU from client
        /// Wait Font List PDU
        /// @param s: Buffer from transport layer
        void recvClientControlRequestPDU(Buffer *s);

        /// @summary: Last synchronize packet from client to server
        /// Send Server Finalize PDUs
        /// Wait any PDU
        /// @param s: Buffer from transport layer
        void recvClientFontListPDU(Buffer *s);

        /// @summary: Main receive function after connection sequence
        /// @param s: Buffer from transport layer
        void recvPDU(Buffer *s);

        /// @summary: read a data PDU object
        /// @param dataPDU: DataPDU object
        void readDataPDU(Buffer *s, uint16_t readLen);

        /// @summary: Implement IFastPathListener interface
        /// Fast path is needed by RDP 8.0
        /// @param fastPathS : Buffer that contain fast path data
        void recvFastPath(uint16_t secFlag, Buffer *fastPathS);

        /// @summary: Send server capabilities server automata PDU
        void sendDemandActivePDU();

        /// @summary: Send last synchronize packet from server to client
        void sendServerFinalizeSynchronizePDU();

        /// @summary: Send a PDU data to transport layer
        /// @param pduMessage: PDU message
        void sendPDU(uint16_t pduType, Buffer *pduMessage);

        /// @summary: Send bitmap update data
        /// @param bitmapDatas: List of data.BitmapData
        void sendBitmapUpdatePDU(std::vector<BitmapDataPtr> &bitmapDatas);

    private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(ServerPDULayer);

        PduServerListener *_listener;
    };

} // namespace rdpp

#endif // _RDPP_RDP_PDU_LAYER_H_
