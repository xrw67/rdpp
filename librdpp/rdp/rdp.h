#ifndef _RDPP_RDP_RDP_H_
#define _RDPP_RDP_RDP_H_

#include <core/config.h>
#include <core/buffer.h>
#include <core/layer.h>
#include <rdp/pdu/layer.h>
#include <vector>
#include <list>

namespace rdpp {

    class CSSP;
	class NTLMv2;
    class TPKTLayer;
    class ClientX224Layer;
    class ServerX224Layer;
    class ClientSecLayer;
    class ServerSecLayer;
    class ClientMCSLayer;
    class ServerMCSLayer;
    class ClientPDULayer;
    class ServerPDULayer;

    /// @summary: RDP security level
    enum SecurityLevel {
        RDP_LEVEL_RDP = 0,
        RDP_LEVEL_SSL = 1,
        RDP_LEVEL_NLA = 2,
    };

	/// @summary: Class use to inform all RDP event handle
	class RDPClientObserver
	{
	public:
		/// @summary: Stack is ready and connected
		virtual void onReady() = 0;

		/// @summary: Windows session is ready
		virtual void onSessionReady() = 0;

		///  @summary: Stack is closes
		virtual void onClose() = 0;

		/// @summary: Notify bitmap update
		virtual void onUpdate(uint16_t destLeft, uint16_t destTop, uint16_t destRight,
							  uint16_t destBottom, uint16_t width, uint16_t height,
							  uint16_t bitsPerPixel, bool isCompress, const string &data) = 0;
	};

	/// @summary: Class use to inform all RDP event handle
	class RDPServerObserver
	{
	public:
		/// @summary: Stack is ready and connected
        ///            May be called after an setColorDepth too
		virtual void onReady() = 0;

		/// @summary: Stack is closes
		virtual void onClose() = 0;

		/// @summary: Event call when a keyboard event is catch in scan code format
		/// @param code: {integer} scan code of key
		/// @param isPressed: {boolean} True if key is down
		/// @param isExtended: {boolean} True if a special key
		virtual void onKeyEventScancode(uint32_t code, bool isPressed, bool isExtended) = 0;

		/// @summary: Event call when a keyboard event is catch in unicode format
		/// @param code: unicode of key
		/// @param isPressed: True if key is down
		virtual void onKeyEventUnicode(uint32_t code, bool isPressed) = 0;

		/// @summary: Event call on mouse event
		/// @param x: x position
		/// @param y: y position
		/// @param button: 1, 2 or 3 button
		/// @param isPressed: True if mouse button is pressed
		virtual void onPointerEvent(uint16_t x, uint16_t y, uint8_t button, bool isPressed) = 0;
	};

    /// Manage RDP stack as client
    class RDPClientController : public PduClientListener, public NlaConnector
    {
    public:
        explicit RDPClientController(RdpTransport *rdpTransport);
        ~RDPClientController();

		/// @summary: Add observer to RDP protocol
        /// @param observer: new observer to add
		void addClientObserver(RDPClientObserver *observer);

		/// @summary: Remove observer to RDP protocol stack
        /// @param observer: observer to remove
		void removeClientObserver(RDPClientObserver *observer);

		void connect();

        /// @summary: Close protocol stack
        void close();

        /// @summary: use to start NLA (NTLM over SSL) protocol
        ///             must be called after startTLS function
        virtual bool connectNla();

        /// @summary: Receive RAW data from socket
        void transportRecv(Buffer *data);

		void setSSL(void *ssl)
		{ _ssl = ssl; };

        /// @return: color depth set by the server (15, 16, 24)
        uint16_t getColorDepth();

        /// @return: True if server support unicode input
        bool getKeyEventUnicodeSupport();

        /// @summary: Set particular flag in RDP stack to avoid wall-paper,
        ///           theme, menu animation etc...
        void setPerformanceSession();

        /// @summary: Set screen dim of session
        /// @param width: width in pixel of screen
        /// @param height: height in pixel of screen
        void setScreen(uint16_t width, uint16_t height);

        /// @summary: Set the username for session
        /// @param username: {string} username of session
        void setUsername(const string &username);
        /// @summary: Set password for session
        /// @param password: {string} password of session
        void setPassword(const string &password);

        /// @summary: Set the windows domain of session
        /// @param domain: {string} domain of session
        void setDomain(const string &domain);

        /// @summary: enable autologon
        void setAutologon();

        /// @summary: set application name of app which start at the begining of session
        /// @param appName: {string} application name
        void setAlternateShell(const string &appName);

        /// @summary: keyboard layout
        /// @param layout: us | fr
        void setKeyboardLayout(const string &layout);

        /// @summary: set hostname of machine
        void setHostname(const string &hostname);

        /// @summary: Request basic security
        /// @param level: {SecurityLevel}
        void setSecurityLevel(int level);

        /// @summary: send pointer events
        /// @param x: x position of pointer
        /// @param y: y position of pointer
        /// @param button: 1 or 2 or 3
        /// @param isPressed: true if button is pressed or false if it's released
        void sendPointerEvent(uint16_t x, uint16_t y, uint8_t button, bool isPressed);

        /// @summary: Call when a bitmap data is received from update PDU
        /// @param rectangles: [pdu.BitmapData] struct
        void onUpdate(std::vector<BitmapDataPtr> &rectangles);

        /// @summary: Call when PDU layer is connected
        void onReady();

        /// @summary: Call when Windows session is ready (connected)
        void onSessionReady();

        /// @summary: Event call when RDP stack is closed
        void onClose();

        /// @summary: Send a mouse wheel event
        /// @param x: x position of pointer
        /// @param y: y position of pointer
        /// @param step: number of step rolled
        /// @param isHorizontal: horizontal wheel (default is vertical)
        /// @param isNegative: is upper (default down)
        void sendWheelEvent(uint16_t x, uint16_t y, uint8_t step,
        bool isNegative = false, bool isHorizontal = false);

        /// @summary: Send a scan code to RDP stack
        /// @param code: scan code
        /// @param isPressed: True if key is pressed and false if it's released
        /// @param extended: {boolean} extended scancode like ctr or win button
        void sendKeyEventScancode(uint32_t code, bool isPressed, bool extended = false);

        /// @summary: Send a scan code to RDP stack
        /// @param code: unicode
        /// @param isPressed: True if key is pressed and false if it's released
        void sendKeyEventUnicode(uint32_t code, bool isPressed);

        /// @summary: Force server to resend a particular zone
        /// @param left: left coordinate
        /// @param top: top coordinate
        /// @param right: right coordinate
        /// @param bottom: bottom coordinate
        void sendRefreshOrder(uint16_t left, uint16_t top, uint16_t right, uint16_t bottom);

    private:
        RDPP_DISALLOW_EVIL_CONSTRUCTORS(RDPClientController);
        
		// list of observer
		typedef std::list<RDPClientObserver *> RDPClientObserverList;
		RDPClientObserverList _clientObservers;

        bool _isReady;
		void *_ssl;

        // PDU layer
        ClientPDULayer *_pduLayer;
        ClientSecLayer *_secLayer;
        ClientMCSLayer *_mcsLayer;
        ClientX224Layer *_x224Layer;
        TPKTLayer *_tpktLayer;
       
		// CredSSP
		NTLMv2 *_ntlm;
		CSSP *_cssp;
    };
    
    /// @summary: Controller use in server side mode
    class RDPServerController : PduServerListener
    {
    public:
        /// @param privateKeyFileName: file contain server private key
        /// @param certficiateFileName: file that contain public key
        /// @param colorDepth: 15, 16, 24
        explicit RDPServerController(uint8_t colorDepth, RdpTransport *rdpTransport);
        ~RDPServerController();

		/// @summary: Add observer to RDP protocol
        /// @param observer: new observer to add
		void addServerObserver(RDPServerObserver *observer);

		/// @summary: Remove observer to RDP protocol stack
        /// @param observer: observer to remove
		void removeServerObserver(RDPServerObserver *observer);

		void listen();

        /// @summary: Close protocol stack
        void close();

		/// @summary: Receive RAW data from socket
        void transportRecv(Buffer *data);

        /// @return: name of client (information done by RDP)
        string getHostname();

        /// @summary: Must be call after on ready event else always empty string
        /// @return: username send by client may be an empty string
        string getUsername();

        /// @summary: Must be call after on ready event else always empty string
        /// @return: password send by client may be an empty string
        string getPassword();

        /// @summary: Must be call after on ready event else always empty string
        /// @return: domain send by client may be an empty string
        string getDomain();

        /// @return: color depth define by server
        uint16_t getColorDepth();

        /// @return: tuple(width, height) of client asked screen
        void getScreen(uint16_t &width, uint16_t &height);

        /// @summary:  Set color depth of session
        ///             if PDU stack is already connected send a deactive-reactive sequence
        ///             and an onReady message is re send when client is ready
        /// @param colorDepth: {integer} depth of session (15, 16, 24)
        void setColorDepth(uint16_t colorDepth);

        ///  @summary: Enable key event in unicode format
        void setKeyEventUnicodeSupport();

        /// @summary: RDP stack is now ready
        void onReady();

        /// @summary: Event call when RDP stack is closed
        void onClose();

        /// @summary: Event call when slow path input are available
        /// @param slowPathInputEvents: [data.SlowPathInputEvent]
        void onSlowPathInput(uint16_t numEvents, Buffer *slowPathInputEvents);

        /// @summary: send bitmap update
        /// @param destLeft: xmin position
        /// @param destTop: ymin position
        /// @param destRight: xmax position because RDP can send bitmap with padding
        /// @param destBottom: ymax position because RDP can send bitmap with padding
        /// @param width: width of bitmap
        /// @param height: height of bitmap
        /// @param bitsPerPixel: number of bit per pixel
        /// @param isCompress: use RLE compression
        /// @param data: bitmap data
        void sendUpdate(uint16_t destLeft, uint16_t destTop, 
                        uint16_t destRight, uint16_t destBottom,
                        uint16_t width, uint16_t height, uint16_t bitsPerPixel,
                        bool isCompress, const string &data);


    private:
        RDPP_DISALLOW_EVIL_CONSTRUCTORS(RDPServerController);

		typedef std::list<RDPServerObserver *> RDPServerObserverList;
		RDPServerObserverList _serverObservers;

        uint16_t _colorDepth;
        bool _isReady;

        // build RDP protocol stack
        ServerPDULayer *_pduLayer; 
        ServerSecLayer *_secLayer;
        ServerMCSLayer *_mcsLayer;
        ServerX224Layer *_x224Layer;
        TPKTLayer *_tpktLayer;
    };

} // namespace rdpp

#endif // _RDPP_RDP_RDP_H_
