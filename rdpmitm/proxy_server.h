#ifndef _RDPP_MITM_PROXY_SERVER_H_
#define _RDPP_MITM_PROXY_SERVER_H_

#include <rdp/rdp.h>
#include <core/rss.h>
#include <ace/Reactor.h>
#include <ace_ssl/SSL_Context.h>
#include <ace_ssl/SSL_SOCK_Stream.h>

namespace rdpp {

    class ProxyClient;

    class ProxyServer : public ACE_Event_Handler, public RdpTransport, public RDPServerObserver
    {
    public:
	    ProxyServer(const string &ip, int port, const string &rssFile,
			        const string &privateKeyFile, const string &certificateFile,
		            int clientSecurity, ACE_Reactor *reactor);
	    ~ProxyServer();
		
		bool open();

		FileRecorder *rss()
		{ return &_rss; }

        ACE_SSL_SOCK_Stream &peer()
		{ return _stream; }

        RDPServerController *controller()
		{ return _controller.get(); }

	    void setClient(ProxyClient *client)
		{ _client = client; }

	    virtual ACE_HANDLE get_handle() const
		{ return _stream.get_handle(); }

	    virtual int handle_input(ACE_HANDLE fd);
	    virtual int handle_close(ACE_HANDLE fd, ACE_Reactor_Mask mask);

		
		virtual void transportSend(Buffer *data);
		virtual void transportClose();
		virtual bool startTls();
		virtual bool isTlsSupport();

		virtual void onReady();
        virtual void onClose();
        virtual void onKeyEventScancode(uint32_t code, bool isPressed, bool isExtended);
        virtual void onKeyEventUnicode(uint32_t code, bool isPressed);
        virtual void onPointerEvent(uint16_t x, uint16_t y, uint8_t button, bool isPressed);

    private:
		string _ip;
	    int _port;
        bool _sslEnabled;
		ACE_Reactor *_reactor;
        ACE_SSL_Context _context;
        ACE_SSL_SOCK_Stream _stream;
	    ProxyClient *_client;
	    shared_ptr<RDPServerController> _controller;
	    Buffer _readBuffer;
	    ACE_INET_Addr _serverAddr;
	    int _clientSecurityLevel;
		string _privateKeyFile;
		string _certificateFile;
		FileRecorder _rss;
};

} // namespace rdpp

#endif // _RDPP_MITM_PROXY_SERVER_H_
